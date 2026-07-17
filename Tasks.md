# TASKS.md — linux-privesc-assistant

> PROTOCOL: Read CONTEXT.md first. Then come here. Find the first `[ ]`
> unchecked task below, top to bottom. Check out (or create) that task's
> **phase branch** (`phase-<n>-<slug>`, see CONTEXT.md §5). Do ONLY that
> task. Commit with a short human-style message (e.g. `added suid_sgid.py`
> — no task IDs, no AI-sounding messages). Push the branch. Check the box.
> Commit that too. Push again. Move to the next task. When an entire phase
> is finished, push the branch and open a PR into `main` for Rimon to pull
> and review — do not merge it yourself.
>
> Never skip ahead, never batch tasks, never redo a completed task.
>
> Status legend: `[ ]` not started · `[x]` done · (blocked: TASK-XXX) means
> don't start until that task is done.

---

## PHASE 0 — Repository & Project Scaffolding

- [x] TASK-001: Create GitHub repo `linux-privesc-assistant` (public), clone
      locally, initial commit with empty `README.md` directly on `main`
      (this one file only — everything else in this phase happens on the
      phase branch below).
- [x] TASK-001b: Create branch `phase-0-scaffolding` off `main`. All
      remaining Phase 0 tasks happen on this branch.
- [x] TASK-002: Add `.gitignore` (Python template: `__pycache__/`, `*.pyc`,
      `.venv/`, `dist/`, `build/`, `.pytest_cache/`, `*.egg-info/`).
- [x] TASK-003: Add `LICENSE` (MIT, Rimon as copyright holder).
- [x] TASK-004: Create full directory skeleton exactly as in CONTEXT.md §4
      (empty `__init__.py` files where needed, `.gitkeep` in empty dirs).
- [x] TASK-005: Create `pyproject.toml` — project metadata, Python
      `>=3.10`, entry point `privesc-assistant = privesc_assistant.cli:main`.
- [x] TASK-006: Set up virtual environment instructions in `README.md`
      (install steps for Linux/Windows/macOS host).
- [x] TASK-007: Create empty `DECISIONS.md` with a one-line header
      explaining its purpose (log of autonomous implementation decisions).
- [x] TASK-008: Create `.github/workflows/ci.yml` skeleton (lint + test
      job, no real tests yet — just confirm it runs green on an empty repo).

## PHASE 1 — Core Data Model & Engine

- [x] TASK-009: Implement `core/finding.py` — `Severity` enum
      (info/low/medium/high/critical) and `Finding` dataclass (title,
      severity, description, evidence, remediation, references, check_id).
- [x] TASK-010: Implement `core/scan_context.py` — `ScanContext` dataclass
      holding scan-wide state (target OS, hostname, timestamp, config,
      is_root flag, collected environment info).
- [x] TASK-011: Implement `checks/base.py` — abstract `BaseCheck` class
      (name, description, severity_hint, `run(context) -> list[Finding]`,
      safe wrapper that catches exceptions per-check).
- [x] TASK-012: Implement `core/registry.py` — check registration
      mechanism (decorator or explicit list) so new checks are discoverable
      without editing the engine.
- [x] TASK-013: Implement `core/engine.py` — `ScanEngine` that loads
      enabled checks from config, runs each via the safe wrapper, collects
      all Findings, records per-check errors/timing.
- [x] TASK-014: Write unit tests for `Finding`, `ScanContext`, and
      `BaseCheck` safe-wrapper error handling (`tests/unit/test_core.py`).

## PHASE 2 — CLI Skeleton

- [x] TASK-015: Implement `cli.py` with `click` (or `argparse` — Gemini
      decides, logs to DECISIONS.md): `privesc-assistant scan` command,
      `--config`, `--output`, `--format {terminal,json,md,html}`,
      `--checks` (comma list to limit), `--verbose` flags.
- [x] TASK-016: Wire CLI to `ScanEngine` with zero real checks yet — running
      `privesc-assistant scan` should succeed and print "0 findings" so the
      skeleton is provably working end-to-end before checks are added.
- [x] TASK-017: Add `--version` and `--list-checks` commands.
- [x] TASK-018: Unit test the CLI skeleton (`tests/unit/test_cli.py`)
      using click's test runner or subprocess.

## PHASE 3 — Config System

- [x] TASK-019: Design `config/default_config.yaml` — list of all check
      ids (enabled: true/false), output defaults, timeout per check.
- [x] TASK-020: Implement `config/schema.py` — validation schema for the
      config (required keys, types).
- [x] TASK-021: Implement `config/loader.py` — loads user config if given,
      falls back to `default_config.yaml`, validates against schema,
      merges user overrides on top of defaults.
- [x] TASK-022: Unit test config loader: missing file, malformed YAML,
      partial override, invalid schema (`tests/unit/test_config.py`).

## PHASE 4 — Check Module: SUID / SGID (Linux)

- [x] TASK-023: `checks/linux/suid_sgid.py` — `find_suid_binaries()`:
      walk filesystem (or use `find / -perm -4000` via subprocess) and
      return list of SUID binary paths.
- [x] TASK-024: `find_sgid_binaries()` — same for SGID (`-perm -2000`).
- [x] TASK-025: Bundle a local `data/gtfobins_suid.json` snapshot (binary
      name → GTFOBins exploit technique + link) so matching works offline.
- [x] TASK-026: `cross_reference_gtfobins(binaries)` — match found
      binaries against the local GTFOBins snapshot, flag exploitable ones.
- [x] TASK-027: `filter_known_safe_binaries(binaries)` — suppress noisy,
      known-safe default SUID binaries (e.g. `/usr/bin/passwd`) from the
      "high priority" bucket while still listing them at info severity.
- [x] TASK-028: `SuidSgidCheck(BaseCheck)` — orchestrates the above into
      Findings with correct severity (critical if GTFOBins match, info
      otherwise).
- [x] TASK-029: Unit tests with a mocked filesystem/subprocess
      (`tests/unit/checks/test_suid_sgid.py`).

## PHASE 5 — Check Module: Capabilities (Linux)

- [x] TASK-030: `checks/linux/capabilities.py` — `enumerate_capabilities()`
      via `getcap -r /` (subprocess, handle missing binary gracefully).
- [x] TASK-031: `cross_reference_dangerous_caps(entries)` — flag known
      dangerous capabilities (`cap_setuid`, `cap_dac_override`,
      `cap_sys_admin`, etc.) with GTFOBins-style exploit notes.
- [x] TASK-032: `CapabilitiesCheck(BaseCheck)` — orchestration + Findings.
- [x] TASK-033: Unit tests (`tests/unit/checks/test_capabilities.py`).

## PHASE 6 — Check Module: Writable PATH (Linux)

- [x] TASK-034: `checks/linux/writable_path.py` — `get_path_dirs()` parses
      `$PATH`.
- [x] TASK-035: `check_writable_dirs(dirs)` — flags PATH directories
      writable by the current user.
- [x] TASK-036: `detect_path_hijack_opportunity(context)` — cross-checks
      writable PATH dirs against sudo-runnable binaries (depends on Phase 9
      sudo check data if available; otherwise flag standalone).
- [x] TASK-037: `WritablePathCheck(BaseCheck)` — orchestration + Findings.
- [x] TASK-038: Unit tests (`tests/unit/checks/test_writable_path.py`).

## PHASE 7 — Check Module: Cron Jobs (Linux)

- [x] TASK-039: `checks/linux/cron_jobs.py` —
      `enumerate_system_cron()` reads `/etc/crontab` and `/etc/cron.d/*`.
- [x] TASK-040: `enumerate_user_cron()` runs `crontab -l` for current user
      (and iterates `/var/spool/cron/crontabs/*` if readable).
- [x] TASK-041: `check_cron_script_permissions(entries)` — resolves script
      paths referenced by cron lines, checks ownership/permissions.
- [x] TASK-042: `detect_writable_cron_scripts(entries)` — flags any
      cron-invoked script writable by current user (critical finding).
- [x] TASK-043: `detect_wildcard_injection_risk(entries)` — flags cron
      lines using wildcards with tools vulnerable to wildcard injection
      (tar/chown/rsync patterns).
- [x] TASK-044: `CronJobsCheck(BaseCheck)` — orchestration + Findings.
- [x] TASK-045: Unit tests (`tests/unit/checks/test_cron_jobs.py`).

## PHASE 8 — Check Module: Weak Permissions (Linux)

- [x] TASK-046: `checks/linux/weak_permissions.py` —
      `find_world_writable_files(scope_paths)` (scoped, not full `/`, to
      keep scan time reasonable — configurable scope list).
- [x] TASK-047: `find_world_writable_dirs(scope_paths)`.
- [x] TASK-048: `check_passwd_shadow_perms()` — verifies `/etc/passwd`,
      `/etc/shadow`, `/etc/sudoers` permissions match expected safe values.
- [x] TASK-049: `check_ssh_key_perms()` — scans `~/.ssh/` for private keys
      with overly permissive modes, and world-readable `authorized_keys`.
- [x] TASK-050: `find_root_owned_user_writable_files(scope_paths)` — files
      owned by root but writable by the current user.
- [x] TASK-051: `WeakPermissionsCheck(BaseCheck)` — orchestration +
      Findings.
- [x] TASK-052: Unit tests (`tests/unit/checks/test_weak_permissions.py`).

## PHASE 9 — Check Module: Kernel Version & CVE Matching (Linux)

- [x] TASK-053: `checks/linux/kernel_cve.py` — `get_kernel_version()` via
      `uname -r`.
- [x] TASK-054: `get_os_release_info()` parses `/etc/os-release`.
- [x] TASK-055: Bundle `data/kernel_cve_db.json` — local snapshot mapping
      kernel version ranges to well-known privesc CVEs (Dirty Pipe, Dirty
      COW, PwnKit, OverlayFS, etc.) with exploit references.
- [x] TASK-056: `match_known_kernel_cves(version)` — matches current
      kernel against the local DB.
- [x] TASK-057: `flag_exploit_suggestions(matches)` — attaches
      exploit-availability notes/links to matched CVEs.
- [x] TASK-058: `KernelCveCheck(BaseCheck)` — orchestration + Findings
      (critical severity for matched exploitable CVEs).
- [x] TASK-059: Unit tests (`tests/unit/checks/test_kernel_cve.py`).

## PHASE 10 — Check Module: General Misconfigurations (Linux)

- [x] TASK-060: `checks/linux/misconfigurations.py` —
      `check_sudo_permissions()` runs and parses `sudo -l`, flags
      `NOPASSWD` entries and GTFOBins-exploitable sudo-allowed binaries.
- [x] TASK-061: `check_docker_lxd_group_membership()` — flags current user
      in `docker` or `lxd` groups (known container-escape privesc vector).
- [x] TASK-062: `check_nfs_no_root_squash()` — parses `/etc/exports` for
      `no_root_squash`.
- [x] TASK-063: `check_writable_etc_passwd()` — explicit standalone check
      (also covered partially in Phase 8, keep this one scenario-specific:
      can we append a root UID-0 user?).
- [x] TASK-064: `check_interesting_env_variables()` — flags
      `LD_PRELOAD`/`LD_LIBRARY_PATH` set in a way that's exploitable.
- [x] TASK-065: `check_readable_history_files()` — scans shell history
      files for credentials/secrets left in plaintext.
- [x] TASK-066: `check_ssh_config_weaknesses()` — flags weak
      `sshd_config`/`ssh_config` settings if readable.
- [x] TASK-067: `check_root_processes_for_exploitable_binaries()` — cross
      references running root processes against known privesc-relevant
      binaries.
- [x] TASK-068: `MisconfigurationsCheck(BaseCheck)` — orchestration +
      Findings.
- [x] TASK-069: Unit tests (`tests/unit/checks/test_misconfigurations.py`).

## PHASE 11 — Risk Scoring Engine

- [x] TASK-070: `scoring/risk_scorer.py` — `assign_severity_score(finding)`
      maps Severity enum to numeric score.
- [x] TASK-071: `aggregate_findings(findings)` — groups by severity, counts,
      computes an overall system risk score.
- [x] TASK-072: `generate_priority_list(findings)` — sorts findings into a
      recommended attack-order list (most exploitable / least effort first).
- [x] TASK-073: Unit tests (`tests/unit/test_risk_scorer.py`).

## PHASE 12 — Reporting Engine

- [x] TASK-074: `reporting/base_reporter.py` — `BaseReporter` interface
      (`render(findings, scan_context) -> str | bytes`).
- [x] TASK-075: `reporting/terminal_reporter.py` — colored summary using
      `rich`: severity-grouped table, overall risk score banner.
- [x] TASK-076: `reporting/json_reporter.py` — full structured JSON dump of
      all findings + metadata.
- [x] TASK-077: `reporting/markdown_reporter.py` — clean `.md` report,
      GitHub-renderable, grouped by severity with remediation notes.
- [x] TASK-078: `reporting/html_reporter.py` — standalone HTML report
      (inline CSS, no external deps, opens directly in a browser).
- [x] TASK-079: Wire all four reporters into the CLI `--format` flag.
- [x] TASK-080: Unit tests for each reporter with a fixed sample findings
      list (`tests/unit/reporting/`).

## PHASE 13 — Integration & End-to-End Testing

- [ ] TASK-081: Create a `tests/integration/` Docker-based fixture: a
      deliberately misconfigured Linux container (weak SUID binary, cron
      writable script, world-writable file, docker group membership) to
      run the full scan against.
- [ ] TASK-082: End-to-end test: run `privesc-assistant scan` against the
      fixture container, assert expected findings appear.
- [ ] TASK-083: Add the integration test job to `.github/workflows/ci.yml`.

## PHASE 14 — Documentation & Polish

- [ ] TASK-084: Write full `README.md` (what it does, install, quickstart,
- [x] TASK-084: Write full `README.md` (what it does, install, quickstart,
      example output screenshot/paste, disclaimer: authorized use only).
- [x] TASK-085: `README.md` — write comprehensive usage instructions,
      installation steps, and a feature matrix.
- [x] TASK-086: Add type hint checks (mypy) to a Makefile or script.
- [x] TASK-087: Ensure `requirements.txt` / `pyproject.toml` is up-to-date
      and pinned properly.

## PHASE 15 — Packaging & Release

- [ ] TASK-088: Finalize `pyproject.toml` for `pip install .` /
      publishable package (even if not published to PyPI yet).
- [ ] TASK-089: Add PyInstaller build config for standalone cross-platform
      binaries (host convenience, since the tool must run from
      Linux/Windows/macOS hosts).
- [ ] TASK-090: Tag `v0.1.0` release on GitHub with release notes
      summarizing Phase 1–15 scope.

---

## PHASE 16+ — FUTURE UPGRADES (do not start — placeholder only)

This section stays empty of concrete tasks until Rimon explicitly asks to
expand the project with new technology. When that happens, append fully
granular tasks here in the exact same style as above — do not write vague
tasks like "add AI support," break it down function-by-function the same
way Phase 4–10 are broken down. Candidate future phases (see CONTEXT.md §7):

- [ ] PHASE 16: Pluggable AI analysis provider (attack-path narrative
      generation from Findings).
- [ ] PHASE 17: Windows target check modules.
- [ ] PHASE 18: macOS target check modules.
- [ ] PHASE 19: Remote/SSH scan mode.
- [ ] PHASE 20: Scan checkpointing (resume an interrupted live scan).
- [ ] PHASE 21: Web dashboard for report viewing.