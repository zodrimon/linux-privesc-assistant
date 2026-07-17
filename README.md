<div align="center">

# 🛡️ Linux PrivEsc Assistant

**A lightweight, standard-library-first Python engine for automating Linux local privilege escalation checks.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/zodrimon/linux-privesc-assistant/graphs/commit-activity)
[![Security](https://img.shields.io/badge/Security-Educational%20Only-red.svg)](#disclaimer)

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Configuration](#configuration) • [Extending](#extending)

</div>

---

## 📖 Overview

The **Linux PrivEsc Assistant** is designed for security professionals, penetration testers, and CTF players. It automates the tedious enumeration of common Linux misconfigurations and security flaws without modifying the target system. 

By strictly adhering to a **standard-library-first** philosophy, this tool can run on almost any Linux system without requiring complex dependency installations, making it perfect for constrained environments.

---

## ✨ Features

The engine systematically checks for the following vectors:

| Check Name | Description | Severity |
|------------|-------------|----------|
| **`suid_sgid`** | Scans for SUID/SGID files and cross-references them against a local **GTFOBins** database to identify immediate exploit vectors. | 🔴 CRITICAL |
| **`capabilities`** | Identifies binaries with dangerous Linux capabilities (`cap_setuid`, `cap_sys_admin`, etc.). | 🔴 CRITICAL |
| **`cron_jobs`** | Analyzes system and user crontabs for writable scripts and potential wildcard injection vulnerabilities. | 🔴 CRITICAL |
| **`weak_permissions`** | Finds world-writable files, root-owned user-writable files, and misconfigured critical files (e.g., `/etc/shadow`, SSH keys). | 🟠 HIGH |
| **`kernel_cve`** | Compares the running kernel version against a local database of known privesc CVEs (e.g., Dirty COW, Dirty Pipe). | 🟠 HIGH |
| **`misconfigurations`** | Checks for dangerous `sudo` rules (`NOPASSWD`), container group memberships (`docker`, `lxd`), and unsafe NFS exports (`no_root_squash`). | 🟡 MEDIUM |
| **`writable_path`** | Detects directories in the current user's `$PATH` that are world-writable or group-writable. | 🟡 MEDIUM |

### 📊 Comprehensive Reporting

Aggregates findings, assigns a risk score, and generates prioritized reports in your preferred format:
- **Terminal (Rich)**: Colored, tabular output for immediate feedback.
- **Markdown**: Clean GitHub-flavored Markdown for documentation.
- **HTML**: Standalone HTML report (no external CSS/JS) for easy sharing.
- **JSON**: Structured dump for integration into other pipelines.

---

## 🚀 Installation

Because this tool targets minimal dependencies, installation is extremely simple.

### 1. Clone the repository
```bash
git clone https://github.com/zodrimon/linux-privesc-assistant.git
cd linux-privesc-assistant
```

### 2. Install (Optional: Virtual Environment)
It's recommended to install in a virtual environment.
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

*Note: The core engine uses only standard libraries. The only optional dependency is `rich`, which provides beautiful terminal tables. It is installed automatically via the command above.*

---

## 💻 Usage

The tool is invoked via the `privesc-assistant` command (or by running the python module directly).

### Basic Scan
Run a full scan with default settings and print to the terminal:
```bash
privesc-assistant scan
```

### Output Formats
Export the results to an HTML file for a clean graphical view:
```bash
privesc-assistant scan --format html --output report.html
```

Other supported formats: `terminal`, `md` (Markdown), `json`.

### Specific Checks
You can selectively run specific checks using the `--checks` flag:
```bash
privesc-assistant scan --checks suid_sgid,cron_jobs,kernel_cve
```

To see all available checks:
```bash
privesc-assistant list-checks
```

### Advanced Configuration
Override default behaviors (like scanned paths) by passing a custom JSON configuration:
```bash
privesc-assistant scan --config custom_config.json
```

---

## 🛠️ Configuration Example

Create a `custom_config.json` to alter how the checks operate:

```json
{
  "suid_sgid_paths": ["/bin", "/usr/bin", "/sbin", "/usr/sbin"],
  "weak_permissions_scopes": ["/etc", "/var/www"],
  "checks": {
    "suid_sgid": true,
    "kernel_cve": false
  }
}
```

---

## 🧬 Architecture & Extending

The engine is built around a pluggable architecture. Adding a new check is as simple as creating a class that inherits from `BaseCheck` and using the `@register_check` decorator.

```python
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.registry import register_check

@register_check
class MyCustomCheck(BaseCheck):
    @property
    def name(self) -> str: return "custom_check"

    @property
    def description(self) -> str: return "Detects XYZ vulnerability."

    @property
    def severity_hint(self) -> str: return "high"

    def run(self, context) -> list[Finding]:
        # Your enumeration logic here
        return [Finding(...)]
```

---

## ⚠️ Disclaimer

<a name="disclaimer"></a>
> [!CAUTION]
> **This tool is strictly for educational purposes and authorized security testing (e.g., Penetration Testing, Red Teaming, CTFs).**
> 
> The authors and contributors are not responsible for any misuse or damage caused by this program. Do not use this tool on systems you do not own or do not have explicit, written permission to test. Always adhere to local laws and regulations regarding computer security and privacy.

---

<div align="center">
  <i>Built with standard libraries and a focus on operational security.</i>
</div>
