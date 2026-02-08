---
name: skill-security-audit
description: Audit Codex skills (folders containing SKILL.md) for security risks such as hidden content, network calls, shell execution, obfuscated code, destructive commands, credential access, and bundled binaries. Use when reviewing or installing third-party skills, before publishing a skill, or when a skill behaves unexpectedly.
---

# Skill Security Audit

## Overview

Scan a skill folder for risky patterns and produce a clear verdict plus a manual review checklist.

## Quick Start

1) Run the scanner:

```bash
python3 scripts/scan_skill.py /path/to/skill
```

2) If findings exist, open the flagged files and review them manually.

## Workflow

### 1) Identify the target

- Prefer the root folder that contains `SKILL.md`.
- If you only have a single file, you can scan that file path directly.

### 2) Run a scan

- Text report:

```bash
python3 scripts/scan_skill.py /path/to/skill --format text
```

- JSON report (for automation):

```bash
python3 scripts/scan_skill.py /path/to/skill --format json
```

### 3) Interpret results

- **High**: likely unsafe or needs immediate review (network calls + exec, destructive commands, bundled binaries, obfuscated payloads).
- **Medium**: requires careful review (shell execution without network, hidden HTML comments in markdown, credential access patterns).
- **Low**: potential issue but often benign (URLs in documentation, common build tooling).

If any High or Medium findings exist, do not run the skill until a manual review is complete.

## What to Look For

- **Network calls**: `curl`, `wget`, `requests`, `fetch`, `http(s)://`, sockets
- **Terminal execution**: `bash -c`, `sh -c`, `os.system`, `subprocess`, `child_process`
- **Destructive commands**: `rm -rf`, `del /s`, `format`, `mkfs`, shutdown/reboot
- **Hidden content**: HTML comments (`<!-- -->`) inside markdown
- **Obfuscation**: base64 decode, long encoded blobs, eval/exec
- **Bundled binaries**: `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.zip`

## Manual Review Checklist

See `references/manual-review.md` for a complete checklist and triage guidance.

## Resources

### scripts/

- `scan_skill.py`: Static scanner for risky patterns and hidden content.

### references/

- `manual-review.md`: Triage checklist and false-positive guidance.
- `report-format.md`: JSON schema and severity definitions.
