# Manual Review Checklist

Use this checklist after the automated scan, especially when any High or Medium findings appear.

## 1) SKILL.md and references

- Look for hidden content in HTML comments (`<!-- -->`).
- Verify the description and workflow match what the skill actually does.
- Check for instructions that encourage running untrusted scripts or downloading tools.

## 2) Scripts and executables

- Search for shell execution (`bash -c`, `sh -c`, `os.system`, `subprocess`, `child_process`).
- Confirm any command execution is necessary and safe.
- Reject any destructive commands (`rm -rf`, `mkfs`, `format`, shutdown/reboot).

## 3) Network access and exfiltration

- Review any HTTP calls or sockets.
- Ensure network calls are documented, limited, and user-initiated.
- Flag any use of tokens, API keys, or environment secrets.

## 4) Obfuscation and encoded payloads

- Investigate base64 blobs and runtime decoding.
- Look for eval/exec applied to decoded data.

## 5) Bundled binaries and archives

- Treat binaries as High risk unless there is a strong, documented reason.
- Open archives to see what they contain; remove unknown files.

## 6) False positives and benign patterns

- URLs in documentation are usually Low risk.
- Build scripts (lint, test) can trigger exec patterns; confirm they are safe.

If any item is unclear, treat the skill as unsafe until verified.
