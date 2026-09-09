#!/usr/bin/env python3
"""Inspect Linux files, directories, and processes. Use --json for JSON output."""
import argparse
import grp
import json
import pwd
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def read_field(errors, field, operation):
    try:
        return operation()
    except OSError as exc:
        errors.append({
            "field": field,
            "type": type(exc).__name__,
            "errno": exc.errno,
            "message": exc.strerror or str(exc),
        })
        return None


def account_name(lookup, identifier, attribute):
    try:
        return getattr(lookup(identifier), attribute)
    except (KeyError, OSError):
        return None


def metadata(st):
    return {
        "mode": stat.filemode(st.st_mode),
        "permissions_octal": f"{stat.S_IMODE(st.st_mode):04o}",
        "size_bytes": st.st_size,
        "uid": st.st_uid,
        "owner": account_name(pwd.getpwuid, st.st_uid, "pw_name"),
        "gid": st.st_gid,
        "group": account_name(grp.getgrgid, st.st_gid, "gr_name"),
        "inode": st.st_ino,
        "links": st.st_nlink,
        "device": st.st_dev,
        "accessed_ns": st.st_atime_ns,
        "modified_ns": st.st_mtime_ns,
        "changed_ns": st.st_ctime_ns,
    }


def describe_path(path, show_hidden=True):
    errors = []
    result = {"path": str(path), "errors": errors}
    st = read_field(errors, "lstat", path.lstat)
    if st is None:
        return result
    result["metadata"] = metadata(st)

    if stat.S_ISLNK(st.st_mode):
        target = read_field(errors, "symlink_target", path.readlink)
        result["symlink_target"] = str(target) if target is not None else None
        st = read_field(errors, "target_stat", path.stat)
        if st is None:
            return result
        result["target_metadata"] = metadata(st)

    if stat.S_ISDIR(st.st_mode):
        result["entries"] = []
        result["hidden_excluded"] = not show_hidden
        entries = read_field(errors, "list_directory", lambda: list(path.iterdir()))
        if entries is not None:
            for entry in sorted(entries, key=lambda p: p.name):
                if not show_hidden and entry.name.startswith("."):
                    continue
                item = {"name": entry.name, "errors": []}
                entry_st = read_field(item["errors"], "lstat", entry.lstat)
                if entry_st is not None:
                    item["metadata"] = metadata(entry_st)
                    if stat.S_ISLNK(entry_st.st_mode):
                        target = read_field(item["errors"], "symlink_target", entry.readlink)
                        item["symlink_target"] = str(target) if target is not None else None
                result["entries"].append(item)
        return result

    if not stat.S_ISREG(st.st_mode):
        result["content_skipped"] = "Special file: automatic reads may block or have side effects."
        return result

    data = read_field(errors, "content", path.read_bytes)
    if data is not None:
        result["bytes_read"] = len(data)
        try:
            if b"\x00" in data:
                result["content_format"] = "printable_strings"
            else:
                result["text"] = data.decode("utf-8")
                result["content_format"] = "utf-8"
        except UnicodeDecodeError:
            result["content_format"] = "printable_strings"
        if result["content_format"] == "printable_strings":
            result["strings"] = [
                value.decode("ascii") for value in re.findall(rb"[\x20-\x7e]{4,}", data)
            ]
    return result


def enum_processes(limit=0):
    errors = []
    result = {"processes": [], "errors": errors}
    paths = read_field(errors, "list_proc", lambda: list(Path("/proc").iterdir()))
    if paths is None:
        return result

    # Avoid is_dir(): a process disappearing must not silently remove its record.
    pids = sorted((p for p in paths if p.name.isdigit()), key=lambda p: int(p.name))
    selected = pids[:limit] if limit else pids
    result["numeric_entries_observed"] = len(pids)
    result["omitted_by_limit"] = len(pids) - len(selected)

    for path in selected:
        item = {"pid": int(path.name), "errors": []}
        failures = item["errors"]

        raw = read_field(failures, "cmdline", (path / "cmdline").read_bytes)
        item["argv"] = None
        item["cmdline"] = None
        if raw is not None:
            parts = raw.split(b"\x00") if raw else []
            if parts and parts[-1] == b"":
                parts.pop()
            item["argv"] = [part.decode("utf-8", errors="replace") for part in parts]
            item["cmdline"] = " ".join(item["argv"])

        status = read_field(
            failures, "status",
            lambda: (path / "status").read_text(encoding="utf-8", errors="replace"),
        )
        item["status"] = None
        if status is not None:
            item["status"] = {}
            for line in status.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    item["status"][key] = value.strip()

        # Read link text, including " (deleted)"; do not resolve its target.
        executable = read_field(failures, "exe", (path / "exe").readlink)
        item["executable"] = str(executable) if executable is not None else None

        # Every selected PID gets a record, even when all reads fail.
        result["processes"].append(item)

    result["returned"] = len(result["processes"])
    return result


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("LIMIT must be zero or greater")
    return number


def display(value):
    if value is None:
        return "<unavailable>"
    text = str(value)
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in text)


class Palette:
    # Only these program-owned SGR sequences are emitted. Data is escaped first.
    codes = {
        "pink": "1;38;5;198",
        "red": "1;91", "blue": "1;94", "purple": "1;38;5;141",
        "cyan": "96", "yellow": "93", "green": "92", "dim": "90",
        "white": "97",
    }

    def __call__(self, value, role="white"):
        text = display(value)
        return f"\x1b[{self.codes[role]}m{text}\x1b[0m"


def file_color(name, values=None):
    """Visual priority by name/type only; no claim about file contents or safety."""
    name = Path(name).name.lower()
    suffix = Path(name).suffix
    values = values or {}
    mode = values.get("mode", "")
    permissions = int(values.get("permissions_octal", "0"), 8)
    sensitive = {
        ".ssh", ".gnupg", ".pki", "shadow", "gshadow", "authorized_keys",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials",
        "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml",
        ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    }
    if (name in sensitive or name == ".env" or name.startswith(".env.")
            or suffix in {".key", ".pem", ".p12", ".pfx", ".kdbx"}):
        return "pink"
    if mode.startswith("l"):
        return "purple"
    if permissions & 0o6000 or (permissions & 0o002 and not permissions & 0o1000):
        return "red"
    if mode.startswith("d"):
        return "blue"
    if mode.startswith(("p", "s", "b", "c")) or permissions & 0o111:
        return "red"
    if suffix in {".py", ".sh", ".bash", ".js", ".ts", ".tsx", ".jsx",
                  ".rs", ".go", ".c", ".h", ".cpp", ".java", ".sql"}:
        return "purple"
    if (suffix in {".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml",
                   ".service", ".socket"}
            or name in {".bashrc", ".bash_profile", ".zshrc", ".profile", ".gitconfig"}):
        return "cyan"
    if suffix in {".log", ".db", ".sqlite", ".sqlite3", ".bak", ".old"} or "history" in name:
        return "yellow"
    if suffix in {".zip", ".gz", ".xz", ".zst", ".tar", ".7z", ".rar"}:
        return "green"
    return "dim" if name.startswith(".") else "white"


def print_errors(errors, indent="", colors=None):
    colors = colors or Palette()
    for error in errors:
        print(colors(
            f"{indent}{error['field']}: {error['type']} "
            f"[{error['errno']}] {display(error['message'])}", "red",
        ))


def readable_time(nanoseconds):
    try:
        return datetime.fromtimestamp(nanoseconds / 1_000_000_000).astimezone().isoformat(
            sep=" ", timespec="seconds",
        )
    except (OSError, OverflowError, ValueError):
        return f"{nanoseconds} ns since epoch"


def print_metadata(values, colors=None):
    colors = colors or Palette()
    for key, value in values.items():
        if key.endswith("_ns"):
            print(f"{colors(key[:-3].ljust(18), 'cyan')}: {readable_time(value)}")
        else:
            print(f"{colors(key.ljust(18), 'cyan')}: {display(value)}")


def print_report(report, colors=None):
    colors = colors or Palette()
    if "path_inspection" in report:
        result = report["path_inspection"]
        print(f"Path: {colors(result['path'], file_color(result['path'], result.get('metadata')))}")
        if "symlink_target" in result:
            print(f"Target: {colors(result['symlink_target'], 'purple')}")
        print_errors(result["errors"], colors=colors)

        if "entries" in result:
            print(colors(f"{'MODE':10} {'OCTAL':5} {'BYTES':>10} {'UID:OWNER / GID:GROUP':30} {'MODIFIED':25} NAME", "cyan"))
            for entry in result["entries"]:
                role = file_color(entry["name"], entry.get("metadata"))
                name = colors(entry["name"], role)
                if "symlink_target" in entry:
                    name += f" -> {colors(entry['symlink_target'], 'purple')}"
                values = entry.get("metadata")
                if values is None:
                    print(f"<metadata unavailable> {name}")
                else:
                    ownership = (
                        f"{values['uid']}:{display(values['owner'])} / "
                        f"{values['gid']}:{display(values['group'])}"
                    )
                    print(
                        f"{colors(values['mode'].ljust(10), role)} {values['permissions_octal']:5} "
                        f"{values['size_bytes']:>10} {ownership:30} "
                        f"{readable_time(values['modified_ns']):25} {name}"
                    )
                print_errors(entry["errors"], indent="    ", colors=colors)
            print(colors(f"Entries: {len(result['entries'])}", "cyan"))
        else:
            print_metadata(result.get("metadata", {}), colors)
            if "target_metadata" in result:
                print("Target metadata:")
                print_metadata(result["target_metadata"], colors)
            if "content_skipped" in result:
                print(result["content_skipped"])
            if "bytes_read" in result:
                print(f"--- {result['bytes_read']} bytes; {result['content_format']} ---")
            if "text" in result:
                print(display(result["text"]))
            for string in result.get("strings", []):
                print(display(string))

    if "process_scan" in report:
        scan = report["process_scan"]
        print_errors(scan["errors"], colors=colors)
        for process in scan["processes"]:
            print(colors(f"PID:        {process['pid']}", "pink"))
            print(f"Command:    {colors(process['cmdline'], 'cyan')}")
            print(f"Executable: {colors(process['executable'], 'purple')}")
            if process["status"] is None:
                print("Status:     <unavailable>")
            else:
                for key, value in process["status"].items():
                    print(f"{colors((key + ':').ljust(28), 'blue')} {display(value)}")
            print_errors(process["errors"], colors=colors)
            print(colors("-" * 72, "dim"))
        print(
            f"Observed: {scan.get('numeric_entries_observed', '<unavailable>')}  "
            f"Returned: {len(scan['processes'])}  "
            f"Omitted by limit: {scan.get('omitted_by_limit', 0)}"
        )

    if "jail_check" in report:
        print(f"Jailed/sandboxed: unknown. {report['jail_check']['reason']}")


def print_json(report):
    payload = json.dumps(report, indent=2, ensure_ascii=True)
    try:
        # jq writes directly to stdout: terminal colors, plain JSON in pipes.
        # ASCII output preserves escaping of untrusted non-ASCII controls too.
        result = subprocess.run(
            ["jq", "--ascii-output", "."], input=payload, encoding="ascii",
        )
    except FileNotFoundError:
        print(payload)
        return
    if result.returncode:
        raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default=".")
    parser.add_argument("--no-hidden", action="store_true")
    parser.add_argument("--json", action="store_true", help="output JSON automatically formatted by jq")
    parser.add_argument(
        "--recon-pid", nargs="?", const=0, default=None, type=nonnegative,
        metavar="LIMIT", help="inspect processes; omitted LIMIT or 0 means all visible PIDs",
    )
    parser.add_argument("--check-jail", action="store_true", help="report detection limitations")
    args = parser.parse_args()

    report = {"started_at": datetime.now(timezone.utc).isoformat()}
    if args.recon_pid is not None:
        report["process_scan"] = enum_processes(args.recon_pid)
    else:
        report["path_inspection"] = describe_path(
            Path(args.directory).expanduser(), not args.no_hidden,
        )

    if args.check_jail:
        report["jail_check"] = {
            "jailed_or_sandboxed": None,
            "reason": "Comparing / with /proc/self/root cannot reliably detect confinement.",
        }
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    if args.json:
        print_json(report)
    else:
        print_report(report)


if __name__ == "__main__":
    main()
