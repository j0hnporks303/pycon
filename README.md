# pycon
A python reconnaissance utility.
Gather reconnaissance on potential vulnerabilities in your system, or a system you're authorized to audit. 
Useful for opsec hygiene, red ream education & operation utility

# Install
Download or clone the full repository, then run './install.sh' from the project directory.
Requires Python 3.10 or newer with venv support. The installer creates the virtual environment, installs dependencies & sets up the 'pycon' command.
Use a fresh virtual environment on each machine; do not copy `.venv` between Linux and macOS.
For manual dependency installation, use `python3 -m pip install -r requirements.txt` in your virtual environment.

# Update
Once the updated files have been committed & pushed to GitHub, open a terminal in your existing pycon.d project directory and run:

```bash
git pull --ff-only && ./install.sh
```

Works the same on Linux & macOS. The installer updates dependencies in the project's virtual environment & refreshes the 'pycon' command.
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
- `--check-jail` reports unknown on both platforms; it does not detect sandboxing or containers.

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
  --check-jail          report detection limitations

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
