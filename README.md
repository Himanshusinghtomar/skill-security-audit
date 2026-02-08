# Skill Security Audit

Audit ai skills for risky behavior before installing or publishing. This repository provides a lightweight static scanner plus review guidance to help detect:

- Hidden content in Markdown (HTML comments)
- Network calls and data exfiltration
- Shell execution and command injection
- Destructive commands
- Obfuscated payloads
- Bundled binaries and archives

> Note: Including a `README.md` inside a skill folder is not recommended by the Codex skill spec. This file exists for GitHub users and can be removed if strict compliance is required.

## Quick Start

```bash
python3 scripts/scan_skill.py /path/to/skill
```

- To get JSON output (for CI or automation):

```bash
python3 scripts/scan_skill.py /path/to/skill --format json
```

- To fail CI on high-severity findings:

```bash
python3 scripts/scan_skill.py /path/to/skill --strict
```

## Tool-Specific Setup

### Codex

1) Install the skill:

- Copy this folder into your Codex skills directory (commonly `~/.codex/skills/`).

2) Use it in a prompt:

- `Use $skill-security-audit to scan /path/to/skill before installing it.`

**Run before any other skill**

Codex does not provide a universal built-in “pre-skill hook” that runs before every other skill. To enforce this workflow:

- Make it a policy: always run this skill before installing a new one.
- Add a CI step in your skill repos to run `scripts/scan_skill.py` on each PR.
- If your environment supports hooks, wire this script into the hook so it runs before any skill execution.

### Cursor

Cursor does not currently expose a standardized “skills” system that can be forced to run before other skills across all projects. You can still use this repo in a generic way:

- Run the scanner directly before installing any third‑party skill.
- Add a CI or pre-commit hook to run `scripts/scan_skill.py` on any skill repository.
- If Cursor adds a pre-task or policy hook, wire this script into that hook.

### Claude Code

Claude Code likewise does not offer a universal “pre-skill hook” across all installations. Recommended usage:

- Run the scanner manually before installing or using a skill.
- Add a CI check to any skill repo you maintain.
- If your setup supports hooks or policies, configure them to call `scripts/scan_skill.py` first.

## What It Flags

- **Network calls**: `curl`, `wget`, `requests`, `fetch`, `http(s)://`, sockets
- **Terminal execution**: `bash -c`, `sh -c`, `os.system`, `subprocess`, `child_process`
- **Destructive commands**: `rm -rf`, `format`, `mkfs`, shutdown/reboot
- **Hidden content**: HTML comments in Markdown (`<!-- -->`)
- **Obfuscation**: base64 decode, long encoded blobs, eval/exec
- **Bundled binaries**: `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.zip`

## Output

The scanner produces a verdict plus findings:

- `clean`: no findings
- `review`: medium findings detected
- `danger`: high findings detected

See `references/report-format.md` for the full JSON schema and severity definition.

## Manual Review

Automated results are a starting point. Use the manual checklist:

- `references/manual-review.md`

## Recommended Workflow for Third-Party Skills

1) Clone the skill repository.
2) Run the scanner.
3) If any Medium/High findings exist, review the flagged files.
4) Only install or run the skill after completing manual review.

## Limitations

- Static scanning can miss sophisticated threats.
- Some findings are false positives (e.g., URLs in documentation).
- Binaries are flagged as High risk by default.

## License

Add your license here.
