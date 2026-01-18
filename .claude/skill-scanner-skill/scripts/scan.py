#!/usr/bin/env python3
"""SKILL.md security scanner - detects malicious patterns in skill files."""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Detection rules organized by category
RULES = {
    "prompt-injection": {
        "name": "Prompt Injection Detection",
        "priority": "P0",
        "patterns": [
            ("ignore-previous", r"ignore\s+(all\s+)?previous\s+instructions?", "i", "critical", "Prompt injection: attempt to ignore previous instructions"),
            ("you-are-now", r"you\s+are\s+now", "i", "critical", "Prompt injection: role manipulation attempt"),
            ("system-tag", r"<system>", "i", "critical", "Prompt injection: fake system tag detected"),
            ("new-instructions", r"new\s+instructions?\s*:", "i", "high", "Prompt injection: attempt to inject new instructions"),
            ("forget-previous", r"forget\s+(everything|all|what)", "i", "critical", "Prompt injection: attempt to make agent forget context"),
            ("override-rules", r"(override|bypass|ignore)\s+(safety|security|rules?)", "i", "critical", "Prompt injection: attempt to override safety rules"),
            ("act-as", r"act\s+as\s+(if\s+)?(you\s+are|an?\s+)", "i", "high", "Prompt injection: role impersonation attempt"),
            ("developer-mode", r"(developer|admin|root|sudo)\s+mode", "i", "critical", "Prompt injection: privilege escalation attempt"),
        ]
    },
    "tool-poisoning": {
        "name": "Tool Poisoning Detection",
        "priority": "P1",
        "patterns": [
            ("description-system-tag", r'description:\s*["\']?.*<system>', "i", "critical", "Tool poisoning: system tag in tool description"),
            ("hidden-instructions", r'description:\s*["\']?.*\b(must|always|never|ignore)\b.*instructions?', "i", "high", "Tool poisoning: hidden instructions in description"),
            ("privilege-escalation", r"(sudo|root|admin|elevated)\s+(access|privileges?|permissions?)", "i", "critical", "Tool poisoning: privilege escalation attempt"),
            ("shell-injection-subshell", r"\$\([^)]+\)", "", "critical", "Tool poisoning: shell subshell command injection"),
            ("shell-injection-backtick", r"`[^`]+`", "", "high", "Tool poisoning: backtick command execution"),
            ("shell-injection-rm", r"(;|&&|\|)\s*rm\s", "", "critical", "Tool poisoning: destructive shell command chain"),
            ("shell-injection-pipe", r"\|\s*(sh|bash|zsh|eval)", "", "critical", "Tool poisoning: shell pipe execution"),
            ("execute-arbitrary", r"(exec|eval|spawn)\s*\(", "i", "high", "Tool poisoning: arbitrary code execution pattern"),
            ("hidden-callback", r'(fetch|axios|http\.request|XMLHttpRequest)\s*\(\s*[\'"]https?://', "", "high", "Tool poisoning: external callback attempt"),
            ("fs-operations", r"(fs\.write|fs\.unlink|fs\.rm|rimraf)", "", "high", "Tool poisoning: dangerous filesystem operation"),
        ]
    },
    "data-exfiltration": {
        "name": "Data Exfiltration Detection",
        "priority": "P1",
        "patterns": [
            ("env-access", r"process\.env", "", "high", "Data exfiltration: environment variable access"),
            ("ssh-path", r"~/?\\.ssh/", "", "critical", "Data exfiltration: SSH directory access"),
            ("aws-credentials", r"~/?\\.aws/", "", "critical", "Data exfiltration: AWS credentials access"),
            ("api-key-pattern", r"(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]", "i", "high", "Data exfiltration: API key pattern detected"),
            ("private-key", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "", "critical", "Data exfiltration: private key detected"),
            ("password-pattern", r"(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]", "i", "critical", "Data exfiltration: hardcoded password detected"),
            ("home-directory", r"~/\\.(bash_history|zsh_history|netrc|npmrc)", "", "high", "Data exfiltration: sensitive dotfile access"),
            ("database-url", r"(mongodb|postgresql|mysql|redis)://[^\s]+", "i", "critical", "Data exfiltration: database connection string detected"),
            ("github-token", r"(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]+)", "", "critical", "Data exfiltration: GitHub token pattern detected"),
            ("generic-secret", r"(secret|token|credential)[s]?\s*[=:]\s*['\"][^'\"]{8,}['\"]", "i", "high", "Data exfiltration: potential secret/token detected"),
        ]
    },
    "obfuscation": {
        "name": "Obfuscation Detection",
        "priority": "P1",
        "patterns": [
            ("zero-width-space", "\u200b", "", "high", "Obfuscation: zero-width space character detected"),
            ("rtl-override", "\u202e", "", "critical", "Obfuscation: right-to-left override character detected"),
            ("zero-width-joiner", "\u200d", "", "medium", "Obfuscation: zero-width joiner detected"),
            ("zero-width-non-joiner", "\u200c", "", "medium", "Obfuscation: zero-width non-joiner detected"),
            ("base64-long", r"(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", "", "high", "Obfuscation: long Base64 encoded string detected"),
            ("hex-encoded", r"(?:0x|\\x)[0-9A-Fa-f]{2}(?:(?:0x|\\x)[0-9A-Fa-f]{2}){10,}", "", "high", "Obfuscation: hex-encoded string detected"),
            ("unicode-escape", r"(?:\\u[0-9A-Fa-f]{4}){5,}", "", "medium", "Obfuscation: unicode escape sequence detected"),
            ("html-entities", r"(?:&#x?[0-9A-Fa-f]+;){5,}", "", "medium", "Obfuscation: HTML entity encoding detected"),
            ("invisible-text", r'<span\s+style=["\'].*(?:font-size:\s*0|display:\s*none|visibility:\s*hidden)', "i", "critical", "Obfuscation: invisible text detected (CSS hiding)"),
            ("homoglyph", r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]", "", "high", "Obfuscation: Cyrillic homoglyph detected (potential spoofing)"),
        ]
    },
}

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    pattern_id: str
    message: str
    severity: str
    file_path: str
    line: int
    column: int
    match: str
    priority: str


def scan_content(content: str, file_path: str) -> list[Finding]:
    """Scan content for security issues."""
    findings = []
    lines = content.split("\n")

    for rule_id, rule in RULES.items():
        for pattern_id, pattern, flags, severity, message in rule["patterns"]:
            try:
                regex_flags = re.IGNORECASE if "i" in flags else 0
                regex = re.compile(pattern, regex_flags)

                for line_num, line in enumerate(lines, 1):
                    for match in regex.finditer(line):
                        findings.append(Finding(
                            rule_id=rule_id,
                            rule_name=rule["name"],
                            pattern_id=pattern_id,
                            message=message,
                            severity=severity,
                            file_path=file_path,
                            line=line_num,
                            column=match.start() + 1,
                            match=match.group(0),
                            priority=rule["priority"],
                        ))
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{pattern}': {e}", file=sys.stderr)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 4))

    return findings


def format_console(findings: list[Finding]) -> str:
    """Format findings for console output."""
    if not findings:
        return "\033[36m✓ No security issues found\033[0m\n"

    lines = ["", f"\033[1m\033[31mFound {len(findings)} security issue(s)\033[0m", ""]

    by_severity = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
    colors = {"critical": "\033[31m\033[1m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[34m"}

    for severity in ["critical", "high", "medium", "low"]:
        if severity not in by_severity:
            continue
        sev_findings = by_severity[severity]
        lines.append(f"{colors[severity]}{icons[severity]} {severity.upper()} ({len(sev_findings)})\033[0m")
        lines.append("")

        for f in sev_findings:
            lines.append(f"  \033[90m{f.file_path}:{f.line}:{f.column}\033[0m")
            lines.append(f"  {f.message}")
            lines.append(f"  \033[90mRule: {f.rule_id}/{f.pattern_id}\033[0m")
            lines.append(f'  \033[35mMatch: "{f.match}"\033[0m')
            lines.append("")

    lines.append("\033[1mSummary:\033[0m")
    for severity in ["critical", "high", "medium", "low"]:
        count = len(by_severity.get(severity, []))
        if count > 0:
            lines.append(f"  {icons[severity]} {severity}: {count}")
    lines.append("")

    return "\n".join(lines)


def format_sarif(findings: list[Finding]) -> str:
    """Format findings as SARIF JSON."""
    rules = []
    for rule_id, rule in RULES.items():
        rules.append({
            "id": rule_id,
            "name": rule["name"],
            "shortDescription": {"text": rule["name"]},
            "properties": {"priority": rule["priority"]},
        })

    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results = []
    for f in findings:
        results.append({
            "ruleId": f"{f.rule_id}/{f.pattern_id}",
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skill-scanner",
                    "version": "0.1.0",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def format_json(findings: list[Finding]) -> str:
    """Format findings as JSON."""
    return json.dumps([{
        "rule_id": f.rule_id,
        "pattern_id": f.pattern_id,
        "message": f.message,
        "severity": f.severity,
        "file": f.file_path,
        "line": f.line,
        "column": f.column,
        "match": f.match,
    } for f in findings], indent=2)


def main():
    parser = argparse.ArgumentParser(description="Scan SKILL.md files for security issues")
    parser.add_argument("files", nargs="+", help="Files to scan")
    parser.add_argument("--format", choices=["console", "sarif", "json"], default="console")
    args = parser.parse_args()

    all_findings = []
    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            continue
        content = path.read_text(encoding="utf-8")
        findings = scan_content(content, str(path.resolve()))
        all_findings.extend(findings)

    if args.format == "sarif":
        print(format_sarif(all_findings))
    elif args.format == "json":
        print(format_json(all_findings))
    else:
        print(format_console(all_findings))

    has_critical_or_high = any(f.severity in ("critical", "high") for f in all_findings)
    sys.exit(1 if has_critical_or_high else 0)


if __name__ == "__main__":
    main()
