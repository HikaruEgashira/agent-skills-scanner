/**
 * Shell Script Analyzer
 * Detects dangerous patterns in shell scripts (bash, sh, zsh)
 */

export interface ShellFinding {
  patternId: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  message: string;
  line: number;
  match: string;
  context?: string;
}

interface DangerousPattern {
  id: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  message: string;
  contextLines?: number;
}

const DANGEROUS_SHELL_PATTERNS: DangerousPattern[] = [
  // Command Injection
  {
    id: "shell-command-substitution",
    pattern: /\$\([^)]+\)/,
    severity: "high",
    category: "command-injection",
    message: "Command substitution $() detected - verify input is sanitized",
    contextLines: 1,
  },
  {
    id: "shell-backtick-execution",
    pattern: /`[^`]+`/,
    severity: "high",
    category: "command-injection",
    message: "Backtick command execution detected - verify input is sanitized",
    contextLines: 1,
  },
  {
    id: "shell-eval-command",
    pattern: /\beval\s+/,
    severity: "critical",
    category: "command-injection",
    message: "eval command can execute arbitrary code",
    contextLines: 2,
  },

  // Destructive Commands
  {
    id: "shell-rm-rf",
    pattern: /\brm\s+(-[rf]+|--recursive|--force)/,
    severity: "critical",
    category: "destructive-operation",
    message: "Recursive/forced file deletion (rm -rf) detected",
    contextLines: 2,
  },
  {
    id: "shell-rm-root",
    pattern: /\brm\s+[^;]*\//,
    severity: "critical",
    category: "destructive-operation",
    message: "File deletion targeting root or directory",
    contextLines: 2,
  },
  {
    id: "shell-dd-command",
    pattern: /\bdd\s+if=/,
    severity: "high",
    category: "destructive-operation",
    message: "dd command can overwrite disks/partitions",
    contextLines: 2,
  },
  {
    id: "shell-mkfs",
    pattern: /\bmkfs\./,
    severity: "critical",
    category: "destructive-operation",
    message: "mkfs can destroy filesystem data",
    contextLines: 2,
  },

  // Network Operations
  {
    id: "shell-curl-pipe-sh",
    pattern: /curl\s+[^|]*\|\s*(sh|bash|zsh)/,
    severity: "critical",
    category: "remote-code-execution",
    message: "Piping curl output to shell - downloads and executes remote code",
    contextLines: 2,
  },
  {
    id: "shell-wget-pipe-sh",
    pattern: /wget\s+[^|]*\|\s*(sh|bash|zsh)/,
    severity: "critical",
    category: "remote-code-execution",
    message: "Piping wget output to shell - downloads and executes remote code",
    contextLines: 2,
  },
  {
    id: "shell-curl-output-exec",
    pattern: /curl\s+.*-o\s+\/tmp\/[^\s]+.*&&.*(sh|bash|zsh|chmod\s+\+x)/,
    severity: "critical",
    category: "remote-code-execution",
    message: "Downloading and executing remote script",
    contextLines: 3,
  },

  // Reverse Shells
  {
    id: "shell-nc-reverse",
    pattern: /(nc|netcat|ncat)\s+[^\s]+\s+\d+\s+-e\s*(sh|bash|\/bin\/)/,
    severity: "critical",
    category: "reverse-shell",
    message: "Netcat reverse shell detected",
    contextLines: 2,
  },
  {
    id: "shell-bash-tcp",
    pattern: /bash\s+-i\s+>&\s+\/dev\/tcp\//,
    severity: "critical",
    category: "reverse-shell",
    message: "Bash TCP reverse shell detected",
    contextLines: 2,
  },
  {
    id: "shell-telnet-pipe",
    pattern: /telnet\s+[^\s]+\s+\d+\s*\|\s*\/bin\/bash/,
    severity: "critical",
    category: "reverse-shell",
    message: "Telnet reverse shell detected",
    contextLines: 2,
  },

  // Data Exfiltration
  {
    id: "shell-curl-post-env",
    pattern: /curl\s+.*(-d|--data|--data-raw).*\$/,
    severity: "critical",
    category: "data-exfiltration",
    message: "Curl POST with variable data - potential exfiltration",
    contextLines: 2,
  },
  {
    id: "shell-wget-post-data",
    pattern: /wget\s+.*--post-data.*\$/,
    severity: "critical",
    category: "data-exfiltration",
    message: "Wget POST with variable data - potential exfiltration",
    contextLines: 2,
  },
  {
    id: "shell-env-var-network",
    pattern: /(curl|wget)\s+[^;]*\$[A-Z_]+/,
    severity: "high",
    category: "data-exfiltration",
    message: "Network request contains environment variable",
    contextLines: 2,
  },

  // Credential Access
  {
    id: "shell-read-ssh-key",
    pattern: /\bcat\s+.*\.(ssh|aws).*\/id_rsa/,
    severity: "critical",
    category: "credential-access",
    message: "Reading SSH private key",
    contextLines: 2,
  },
  {
    id: "shell-read-shadow",
    pattern: /\bcat\s+.*\/etc\/shadow/,
    severity: "critical",
    category: "credential-access",
    message: "Reading password shadow file",
    contextLines: 2,
  },
  {
    id: "shell-read-env-file",
    pattern: /\bcat\s+.*\.env/,
    severity: "high",
    category: "credential-access",
    message: "Reading .env file which may contain secrets",
    contextLines: 1,
  },

  // Privilege Escalation
  {
    id: "shell-sudo-nopasswd",
    pattern: /sudo\s+(-S|NOPASSWD)/,
    severity: "critical",
    category: "privilege-escalation",
    message: "Sudo without password prompt",
    contextLines: 2,
  },
  {
    id: "shell-chmod-777",
    pattern: /chmod\s+(777|a\+rwx)/,
    severity: "high",
    category: "privilege-escalation",
    message: "Setting dangerous file permissions (777)",
    contextLines: 1,
  },
  {
    id: "shell-chown-root",
    pattern: /chown\s+root/,
    severity: "high",
    category: "privilege-escalation",
    message: "Changing ownership to root",
    contextLines: 2,
  },

  // Code Obfuscation
  {
    id: "shell-base64-decode",
    pattern: /(base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d)/,
    severity: "high",
    category: "obfuscation",
    message: "Base64 decoding - may hide malicious commands",
    contextLines: 2,
  },
  {
    id: "shell-base64-pipe-sh",
    pattern: /base64\s+(-d|--decode).*\|\s*(sh|bash|zsh)/,
    severity: "critical",
    category: "obfuscation",
    message: "Base64 decode and execute - highly suspicious",
    contextLines: 2,
  },
  {
    id: "shell-xxd-reverse",
    pattern: /xxd\s+-r/,
    severity: "medium",
    category: "obfuscation",
    message: "Hex decode (xxd -r) - may hide malicious content",
    contextLines: 2,
  },

  // Persistence Mechanisms
  {
    id: "shell-crontab-edit",
    pattern: /crontab\s+-[el]/,
    severity: "medium",
    category: "persistence",
    message: "Modifying crontab - potential persistence mechanism",
    contextLines: 2,
  },
  {
    id: "shell-systemd-service",
    pattern: /systemctl\s+(enable|start)\s+[^\s]+\.service/,
    severity: "medium",
    category: "persistence",
    message: "Creating/enabling systemd service",
    contextLines: 2,
  },
  {
    id: "shell-rc-file-modify",
    pattern: /echo\s+.*>>\s*(\.bashrc|\.zshrc|\.profile)/,
    severity: "medium",
    category: "persistence",
    message: "Modifying shell RC files - potential persistence",
    contextLines: 2,
  },

  // History Manipulation
  {
    id: "shell-history-clear",
    pattern: /history\s+(-c|--clear)/,
    severity: "high",
    category: "anti-forensics",
    message: "Clearing command history - anti-forensics",
    contextLines: 1,
  },
  {
    id: "shell-unset-histfile",
    pattern: /unset\s+HISTFILE/,
    severity: "high",
    category: "anti-forensics",
    message: "Disabling history file - anti-forensics",
    contextLines: 1,
  },

  // Process Manipulation
  {
    id: "shell-kill-av",
    pattern: /kill(all)?\s+.*(antivirus|defender|firewall|monitor)/i,
    severity: "critical",
    category: "defense-evasion",
    message: "Killing security software",
    contextLines: 2,
  },
  {
    id: "shell-nohup",
    pattern: /nohup\s+/,
    severity: "medium",
    category: "persistence",
    message: "Nohup keeps process running after logout",
    contextLines: 2,
  },

  // Dangerous Variable Usage
  {
    id: "shell-unquoted-variable",
    pattern: /\$[A-Z_]+[^"'\s]/,
    severity: "medium",
    category: "injection-risk",
    message: "Unquoted variable usage - injection risk",
    contextLines: 1,
  },
];

export class ShellAnalyzer {
  private patterns: DangerousPattern[];

  constructor(customPatterns?: DangerousPattern[]) {
    this.patterns = [...DANGEROUS_SHELL_PATTERNS, ...(customPatterns || [])];
  }

  /**
   * Analyze shell script for security issues
   */
  analyze(code: string, filename?: string): ShellFinding[] {
    const findings: ShellFinding[] = [];
    const lines = code.split("\n");

    for (const pattern of this.patterns) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comments
        const trimmed = line.trim();
        if (trimmed.startsWith("#")) continue;

        const match = line.match(pattern.pattern);

        if (match) {
          // Extract context if specified
          let context: string | undefined;
          if (pattern.contextLines) {
            const start = Math.max(0, i - pattern.contextLines);
            const end = Math.min(lines.length, i + pattern.contextLines + 1);
            context = lines.slice(start, end).join("\n");
          }

          findings.push({
            patternId: pattern.id,
            severity: pattern.severity,
            category: pattern.category,
            message: pattern.message,
            line: i + 1,
            match: match[0].trim(),
            context,
          });
        }
      }
    }

    return findings;
  }

  /**
   * Analyze multiple shell script files
   */
  analyzeFiles(files: Array<{ path: string; content: string }>): Map<string, ShellFinding[]> {
    const results = new Map<string, ShellFinding[]>();

    for (const file of files) {
      // Only analyze shell scripts
      if (this.isShellScript(file.path, file.content)) {
        const findings = this.analyze(file.content, file.path);
        if (findings.length > 0) {
          results.set(file.path, findings);
        }
      }
    }

    return results;
  }

  /**
   * Check if file is a shell script
   */
  private isShellScript(path: string, content: string): boolean {
    // Check file extension
    if (/\.(sh|bash|zsh)$/i.test(path)) return true;

    // Check shebang
    if (content.startsWith("#!/bin/sh") ||
        content.startsWith("#!/bin/bash") ||
        content.startsWith("#!/bin/zsh") ||
        content.startsWith("#!/usr/bin/env bash") ||
        content.startsWith("#!/usr/bin/env sh")) {
      return true;
    }

    return false;
  }

  /**
   * Get statistics about findings
   */
  getStatistics(findings: ShellFinding[]): {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  } {
    const stats = {
      total: findings.length,
      bySeverity: {} as Record<string, number>,
      byCategory: {} as Record<string, number>,
    };

    for (const finding of findings) {
      stats.bySeverity[finding.severity] = (stats.bySeverity[finding.severity] || 0) + 1;
      stats.byCategory[finding.category] = (stats.byCategory[finding.category] || 0) + 1;
    }

    return stats;
  }
}

// Export patterns for testing
export { DANGEROUS_SHELL_PATTERNS };
