# pycon
A python recon utility.
Gather recon on vulnerabilities in your system, or a system you're authorized to audit. 
Useful for red team & blue team security ops.


## Install
git clone https://github.com/j0hnporks303/pycon && cd pycon && ./lzinstall.sh && pycon --help

## USAGE
usage: pycon [-h] [--no-hidden] [--json] [--recon-pid [LIMIT]] [--check-jail] [directory]

Inspect Linux files, directories, and processes. Use --json for JSON output.

positional arguments:
  directory

options:
  -h, --help           show this help message and exit
  --no-hidden
  --json               output JSON automatically formatted by jq
  --recon-pid [LIMIT]  inspect processes; omitted LIMIT or 0 means all visible PIDs
  --check-jail   

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
