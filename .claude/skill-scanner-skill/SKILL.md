---
name: skill-scanner-skill
description: |
  Scan SKILL.md files for security vulnerabilities and malicious patterns.
  Use when: (1) reviewing skills before installation, (2) auditing existing skills,
  (3) checking for prompt injection, data exfiltration, tool poisoning, or obfuscation,
  (4) user asks to "scan skill", "check skill security", or "find malicious skills".
---

# Skill Scanner

Detect security threats in SKILL.md files.

## Threat Categories

| Category | Priority | Examples |
|----------|----------|----------|
| Prompt Injection | P0 | `ignore previous instructions`, `you are now`, `<system>` |
| Tool Poisoning | P1 | `$(rm -rf /)`, `sudo access`, system tags in descriptions |
| Data Exfiltration | P1 | `~/.ssh/`, `process.env`, API keys, tokens |
| Obfuscation | P1 | Zero-width chars, RTL override, Base64, homoglyphs |

## Usage

Scan a skill file:
```bash
python3 scripts/scan.py <path-to-SKILL.md>
```

Scan multiple files:
```bash
python3 scripts/scan.py skill1/SKILL.md skill2/SKILL.md
```

Output formats:
```bash
python3 scripts/scan.py file.md --format console  # default
python3 scripts/scan.py file.md --format json
python3 scripts/scan.py file.md --format sarif    # GitHub Advanced Security
```

## Exit Codes

- `0`: No critical or high severity issues
- `1`: Critical or high severity issues found

## Workflow

1. Run scan on target SKILL.md files
2. Review findings by severity (critical > high > medium > low)
3. Report results to user with file locations and matched patterns
4. Recommend action based on severity (reject if critical/high found)
