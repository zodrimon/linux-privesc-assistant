import os

dirs = [
    ".github/workflows",
    "src/privesc_assistant/core",
    "src/privesc_assistant/checks/linux",
    "src/privesc_assistant/reporting",
    "src/privesc_assistant/scoring",
    "src/privesc_assistant/config",
    "tests/unit",
    "tests/integration",
    "data"
]

for d in dirs:
    os.makedirs(d, exist_ok=True)

files = [
    "src/privesc_assistant/__init__.py",
    "src/privesc_assistant/cli.py",
    "src/privesc_assistant/core/scan_context.py",
    "src/privesc_assistant/core/finding.py",
    "src/privesc_assistant/core/engine.py",
    "src/privesc_assistant/core/registry.py",
    "src/privesc_assistant/checks/base.py",
    "src/privesc_assistant/checks/linux/suid_sgid.py",
    "src/privesc_assistant/checks/linux/capabilities.py",
    "src/privesc_assistant/checks/linux/writable_path.py",
    "src/privesc_assistant/checks/linux/cron_jobs.py",
    "src/privesc_assistant/checks/linux/weak_permissions.py",
    "src/privesc_assistant/checks/linux/kernel_cve.py",
    "src/privesc_assistant/checks/linux/misconfigurations.py",
    "src/privesc_assistant/reporting/base_reporter.py",
    "src/privesc_assistant/reporting/terminal_reporter.py",
    "src/privesc_assistant/reporting/json_reporter.py",
    "src/privesc_assistant/reporting/markdown_reporter.py",
    "src/privesc_assistant/reporting/html_reporter.py",
    "src/privesc_assistant/scoring/risk_scorer.py",
    "src/privesc_assistant/config/default_config.yaml",
    "src/privesc_assistant/config/loader.py",
    "src/privesc_assistant/config/schema.py",
    "tests/unit/.gitkeep",
    "tests/integration/.gitkeep",
    "data/gtfobins_suid.json"
]

for f in files:
    if not os.path.exists(f):
        with open(f, 'w') as fh:
            pass
