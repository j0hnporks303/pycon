# pycon
A python reconnaissance utility.
Gather reconnaissance on potential vulnerabilities in your system, or a system you're authorized to audit. 
Useful for opsec hygiene, red ream education & operation utility

# Install
Download or clone the full repository, then run './install.sh' from the project directory.
Requires an administrator-managed Python 3.10 or newer with venv support. The installer uses sudo to copy the Python program into `/usr/local/bin/pycon` as a root-owned executable file and install its dependencies into a root-owned environment at `/usr/local/lib/pycon/venv`.
The installed command runs independently of the checkout and its `.venv`, using isolated Python imports. Existing links from this checkout are migrated to the copied installation; unrelated installations are preserved.
For development, create a separate `.venv` in the checkout and run `python3 -m pip install -r requirements.txt` in that environment.

# Uninstall
Run `./uninstall.sh`. It removes the managed `/usr/local/bin/pycon` file and `/usr/local/lib/pycon` runtime, requesting sudo when needed. It also supports removing old links from the same checkout.
Project files, `.venv`, and shell PATH settings are kept.

# Update
Once the updated files have been committed & pushed to GitHub, open a terminal in your existing pycon.d project directory and run:

```bash
git pull --ff-only && ./install.sh
```

Works the same on Linux & macOS. The installer updates the system runtime's dependencies and replaces the installed program with a fresh copy. Editing the checkout takes effect only after reinstalling.
If Git reports local changes or diverging branches, resolve those before retrying; do not force the pull.

Check the updated version:

```bash
pycon --help
pycon --recon-pid 3
```

Help should mention Linux and macOS. Process inspection should return up to 3 visible PIDs, with errors shown where access is unavailable.

# Compatibility
Linux and macOS use the same commands. The operating system is detected automatically:

- Linux process inspection (`--recon-pid`) reads `/proc`, preserving the full visible Linux status fields.
- macOS process inspection uses `psutil`, installed automatically on macOS. It reports command arguments, executable paths, names, state, parent PID, user, thread count, and real/effective/saved user and group IDs when accessible. Linux-only status fields are not emulated. JSON includes the backend and limitations.
- Both platforms share file inspection and secret scanning. Permission failures and processes that exit during inspection are reported explicitly; an unavailable value is not evidence that nothing was found.
- macOS privacy controls can restrict access to protected folders even when ordinary Unix permissions allow access. Review Terminal's or your launching application's Files and Folders permissions if a scan reports denied access.
- `--check-jail` checks the current pycon process for isolation indicators. Linux checks Docker/Podman marker files, systemd's container identifier, cgroup membership, seccomp mode, nested PID namespaces visible through procfs, and root-directory differences from visible PID 1. macOS queries its Seatbelt sandbox API. Results include evidence, observations, access errors, and detection limitations.

Validation: Linux tests pass locally. Automated Linux and macOS checks are configured in `.github/workflows/tests.yml`; native macOS results must be checked before treating the port as verified on a Mac.

Native Windows is not currently supported. The program imports the Unix-only `grp` and `pwd` modules at startup, and the installer requires Bash. Windows support needs code changes as well as testing.

# Usage
usage: pycon [-h] [--no-hidden] [--json] [--recon-pid [LIMIT] | --scan-secrets]
             [--secret-engine {regex,detect-secrets,both}] [--recursive] [--max-secret-bytes BYTES] [--check-jail]
             [directory]

Inspect Linux and macOS files, processes, and potential secrets.

positional arguments:
  directory

options:
  -h, --help            show this help message and exit
  --no-hidden
  --json                output JSON automatically formatted by jq
  --recon-pid [LIMIT]   inspect processes; omitted LIMIT or 0 means all visible PIDs
  --scan-secrets        scan file contents; redact findings
  --secret-engine {regex,detect-secrets,both}
                        secret detectors to use (default: both; requires detect-secrets)
  --recursive           scan secrets in subdirectories too
  --max-secret-bytes BYTES
                        skip secret-scan files larger than this (default: 1048576)
  --check-jail          check current process for sandbox/container indicators

`--check-jail` works with file inspection, secret scanning, or process inspection:

```bash
pycon --recon-pid 0 --check-jail
pycon --scan-secrets --recursive --check-jail /path/to/project
pycon --check-jail --json /etc
```

JSON retains `jail_check.jailed_or_sandboxed`: `true` means at least one supported indicator was found; `null` means unknown. It never returns `false` as an assurance that the process is unrestricted. Read `indicators`, `observations`, `errors`, and `limitations` alongside that value. The check concerns pycon's own environment, not the sandbox status of each enumerated PID or the supplied directory.

Container markers and cgroup names are heuristics that can be hidden or forged. A root-directory mismatch suggests a chroot or mount namespace, but matching roots cannot exclude confinement shared with PID 1. Seccomp indicates an active mode, not which syscalls are permitted; `NoNewPrivs` alone is recorded without claiming a sandbox. The macOS check uses a private system API; an unavailable library/symbol or a failed check remains unknown, and a negative Seatbelt result does not exclude TCC, chroots, or other restrictions. macOS behavior is covered by mocked tests; native verification runs in the macOS CI job.

Detection references: [Linux procfs fields](https://www.kernel.org/doc/html/latest/filesystems/proc.html), [seccomp semantics](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), [systemd container detection](https://github.com/systemd/systemd/blob/main/src/basic/virt.c), and [Chromium's macOS Seatbelt runtime check](https://chromium.googlesource.com/chromium/src/+/master/sandbox/mac/seatbelt.cc).

# Colour Codes
## Pink
Sensitive files such as .env, credentials, SSH keys, certs, also process IDs.

## Red
Binaries, executables, errors, world-writable, special files, setuid/setgid perms.

## Blue
Directories & process-status field labels

## Purple
Symbolic links & their targets, source code files, process executable paths

## Cyan
Configuration files, metadata labels, table headings, entry counts, process command lines

## Yellow
Logs, DBs, backups, filenames containing history

## Green
Archives & compressed

## Gray/Dim
Otherwise-unclassified hidden files & process seperators

## White
Default text & otherwise-unclassified visible files

# License
Licensed under the [GNU GPL v3](LICENSE).
