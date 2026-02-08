#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".html", ".css",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".zip", ".gz",
    ".tar", ".tgz", ".7z", ".rar", ".pdf",
}

IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", ".venv", "__pycache__",
}

PATTERNS = {
    "network": [
        r"\b(curl|wget|Invoke-WebRequest|iwr)\b",
        r"\b(requests\.|urllib\.|httpx\.|aiohttp\.|fetch\()",
        r"\b(XMLHttpRequest|socket\.|net\.http|net\.https)\b",
        r"\b(nc|ncat|telnet|ssh|scp|sftp)\b",
        r"https?://",
    ],
    "exec": [
        r"\b(eval|exec)\b",
        r"\b(subprocess\.|os\.system|popen\()",
        r"\b(child_process\.|spawn\(|execFile\(|exec\()",
        r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b",
        r"\b(bash\s+-c|sh\s+-c|cmd\.exe|powershell)\b",
        r"/bin/(sh|bash)",
    ],
    "destructive": [
        r"\brm\s+-rf\b",
        r"\bdel\s+/s\b",
        r"\bformat\b",
        r"\bmkfs\b",
        r"\bshutdown\b",
        r"\breboot\b",
    ],
    "obfuscation": [
        r"\b(base64\.b64decode|atob|fromhex|b64decode)\b",
        r"\b(gzip|zlib)\.(decompress|decompressobj)\b",
        r"\b(eval|exec)\b",
    ],
    "secrets": [
        r"\b(AWS_SECRET|GITHUB_TOKEN|OPENAI_API_KEY|SECRET_KEY)\b",
        r"\bAuthorization:\s*Bearer\b",
        r"\b(token|api[_-]?key|secret)\b",
    ],
    "hidden_content": [
        r"<!--.*?-->",
    ],
}

SEVERITY_BY_CATEGORY = {
    "network": "medium",
    "exec": "medium",
    "destructive": "high",
    "obfuscation": "high",
    "secrets": "medium",
    "hidden_content": "medium",
    "binary": "high",
}


class Finding:
    def __init__(self, severity: str, category: str, path: str, line: Optional[int], snippet: str):
        self.severity = severity
        self.category = category
        self.path = path
        self.line = line
        self.snippet = snippet

    def to_dict(self) -> Dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
        }


def is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path)
    if ext.lower() in TEXT_EXTENSIONS:
        return True
    if ext.lower() in BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
        if not chunk:
            return True
        # Heuristic: if it has null bytes, treat as binary
        return b"\x00" not in chunk
    except OSError:
        return False


def scan_text(path: str, max_size: int) -> List[Finding]:
    findings: List[Finding] = []
    try:
        if os.path.getsize(path) > max_size:
            return findings
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, content, flags=re.IGNORECASE | re.DOTALL):
                line = content.count("\n", 0, match.start()) + 1
                snippet = content[match.start():match.end()]
                severity = SEVERITY_BY_CATEGORY.get(category, "low")
                findings.append(Finding(severity, category, path, line, snippet.strip()))
    return findings


def scan_binary(path: str) -> List[Finding]:
    _, ext = os.path.splitext(path)
    severity = SEVERITY_BY_CATEGORY["binary"]
    return [Finding(severity, "binary", path, None, f"Binary or archive file detected ({ext.lower()})")]


def iter_files(root: str) -> List[str]:
    if os.path.isfile(root):
        return [root]
    paths: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            paths.append(os.path.join(dirpath, name))
    return paths


def verdict(findings: List[Finding]) -> str:
    severities = {f.severity for f in findings}
    if "high" in severities:
        return "danger"
    if "medium" in severities:
        return "review"
    return "clean"


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a skill folder for risky patterns.")
    parser.add_argument("path", help="Skill folder or file to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--max-file-size", type=int, default=2_000_000, help="Max file size to scan (bytes)")
    parser.add_argument("--strict", action="store_true", help="Exit with code 2 if high findings exist")
    args = parser.parse_args()

    paths = iter_files(args.path)
    findings: List[Finding] = []
    skipped: List[str] = []

    for path in paths:
        if is_text_file(path):
            try:
                if os.path.getsize(path) > args.max_file_size:
                    skipped.append(path)
                    continue
            except OSError:
                skipped.append(path)
                continue
            findings.extend(scan_text(path, args.max_file_size))
        else:
            findings.extend(scan_binary(path))

    report = {
        "target": os.path.abspath(args.path),
        "verdict": verdict(findings),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
        "skipped": skipped,
    }

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"Target: {report['target']}")
        print(f"Verdict: {report['verdict']}")
        print(f"Summary: {report['summary']}")
        if skipped:
            print("Skipped (too large or unreadable):")
            for path in skipped:
                print(f"  - {path}")
        if findings:
            print("Findings:")
            for f in findings:
                line = f.line if f.line is not None else "-"
                print(f"  [{f.severity}] {f.category} {f.path}:{line} :: {f.snippet}")
        else:
            print("No findings detected.")

    if args.strict and report["verdict"] == "danger":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
