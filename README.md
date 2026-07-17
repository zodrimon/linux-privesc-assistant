# Linux Privilege Escalation Assistant

A read-only, standard-library-first Python tool designed to detect local privilege escalation vulnerabilities on Linux systems. 

Built for security professionals, penetration testers, and CTF players, this tool automates the enumeration of common misconfigurations without modifying the target system.

## Features

- **SUID/SGID Binaries**: Scans for SUID/SGID files and cross-references them with a local GTFOBins database to identify immediate exploit vectors.
- **Capabilities**: Checks for dangerous Linux capabilities (`cap_setuid`, `cap_sys_admin`, etc.) that can be leveraged for privesc.
- **Writable PATH**: Detects directories in the current user's `$PATH` that are world-writable or group-writable.
- **Cron Jobs**: Analyzes system and user crontabs for writable scripts and potential wildcard injection vulnerabilities.
- **Weak Permissions**: Finds world-writable files/directories, root-owned user-writable files, and misconfigured critical files (`/etc/passwd`, `/etc/shadow`, SSH keys).
- **Kernel Exploits**: Compares the running kernel version against a local database of known privesc CVEs (e.g., Dirty COW, Dirty Pipe).
- **Misconfigurations**: Checks for dangerous sudo rules (`NOPASSWD`), container group memberships (`docker`, `lxd`), unsafe NFS exports (`no_root_squash`), and more.
- **Risk Scoring & Reporting**: Aggregates findings, assigns a severity-based risk score, and generates prioritized reports in Terminal, Markdown, JSON, or HTML formats.

## Installation

```bash
git clone https://github.com/zodrimon/linux-privesc-assistant.git
cd linux-privesc-assistant
pip install -e .
```

*Note: The core engine relies exclusively on the Python standard library. Optional dependencies like `rich` are only required if you want enhanced terminal output.*

## Usage

Run a full scan and output to the terminal:
```bash
privesc-assistant scan
```

Run a scan and output a detailed HTML report:
```bash
privesc-assistant scan --format html --output report.html
```

List all available checks:
```bash
privesc-assistant list-checks
```

Run specific checks only:
```bash
privesc-assistant scan --checks suid_sgid,cron_jobs
```

## Configuration

You can provide a custom configuration file (JSON format) to override default behaviors (e.g., scan scopes, skipped paths).

```bash
privesc-assistant scan --config my_config.json
```

## Testing and Development

To run the test suite:
```bash
python -m unittest discover -s tests
```

To run type checking (requires `mypy`):
```bash
make typecheck
```

## Disclaimer

This tool is for educational and authorized testing purposes only. Do not use it on systems you do not own or do not have explicit permission to test.
