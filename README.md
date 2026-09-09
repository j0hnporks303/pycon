# pycon
A python reconnaissance utility.
Gather reconnaissance on potential vulnerabilities in your system, or a system you're authorized to audit. 
Useful for opsec hygiene, red ream education & operation utility

## Install
git clone https://github.com/j0hnporks303/pycon && cd pycon && ./lzinstall.sh && pycon --help

## USAGE
usage: pycon [-h] [--no-hidden] [--json] [--recon-pid [LIMIT] | --scan-secrets]
             [--secret-engine {regex,detect-secrets,both}] [--recursive]
             [--max-secret-bytes BYTES] [--check-jail] [directory]

Inspect Linux files, directories, and processes. Use --json for JSON output.

positional arguments:
  directory

options:
  -h, --help           show this help message and exit
  --no-hidden
  --json               output JSON automatically formatted by jq
  --recon-pid [LIMIT]  inspect processes; omitted LIMIT or 0 means all visible PIDs
  --check-jail   

## Secret scanning

Scan a file or a directory for potential credentials using the built-in `re`
patterns, with no additional dependencies:

```bash
pycon ./project --scan-secrets --secret-engine regex --recursive
```

The built-in patterns recognize credential assignments, private-key headers, and
URLs containing a username and password. Common placeholders and variable
references are excluded, but false positives and missed secrets are still possible.

For additional provider-specific patterns and entropy detectors, install
[detect-secrets](https://github.com/Yelp/detect-secrets) into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-secrets.txt
.venv/bin/python python_pycon_source.py ./project --scan-secrets --recursive
.venv/bin/python python_pycon_source.py ./project --scan-secrets --recursive --json
```

Secret scanning defaults to both engines. Use `--secret-engine detect-secrets`
to select only that engine. The package must be installed in the Python environment
running pycon; without it, select `regex` or install the optional requirements.

Reports include the path, line number, candidate type, engine, and `[REDACTED]`
instead of source text or credential values. A candidate is not proof of a live
credential. Scanning does not verify credentials with external services. The two
engines may report the same candidate under different categories. Inspect the
indicated line locally to review each finding.

Directory scans include immediate files; `--recursive` includes subdirectories.
Hidden entries are included unless `--no-hidden` is set. `.git`, `.venv`, `venv`,
and `__pycache__` directories, symlinks, special files, binary/non-UTF-8 files, and
files larger than 1 MiB are skipped. Adjust the file limit with
`--max-secret-bytes BYTES`. Skipped paths and read errors appear in the report.
This scans current files, including untracked files, not Git history. Secret mode
does not print the normal file-content report and cannot be combined with process
enumeration. Normal inspection still prints file contents.

For detect-secrets' separate interactive review workflow, activate the virtual
environment, change to the repository you want to audit, then run:

```bash
detect-secrets scan --no-verify > .secrets.baseline
detect-secrets audit .secrets.baseline
```

Its baseline format is separate from pycon's JSON report; the audit command shows
source context locally for review.

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
