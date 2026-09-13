# pycon
A python reconnaissance utility.
Gather reconnaissance on potential vulnerabilities in your system, or a system you're authorized to audit. 
Useful for opsec hygiene, red ream education & operation utility

# Usage
usage: pycon [-h] [--no-hidden] [--json] [--recon-pid [LIMIT] | --scan-secrets]
             [--secret-engine {regex,detect-secrets,both}] [--recursive] [--max-secret-bytes BYTES] [--check-jail]
             [directory]

Inspect Linux files, processes, and potential secrets.

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
