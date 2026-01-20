/**
 * JavaScript/TypeScript Script Analyzer
 * Detects dangerous patterns and API calls in JavaScript/TypeScript code
 */

export interface ScriptFinding {
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

const DANGEROUS_PATTERNS: DangerousPattern[] = [
  // Code Execution
  {
    id: "js-eval",
    pattern: /\beval\s*\(/,
    severity: "critical",
    category: "code-execution",
    message: "Dangerous eval() usage - can execute arbitrary code",
    contextLines: 2,
  },
  {
    id: "js-function-constructor",
    pattern: /new\s+Function\s*\(/,
    severity: "critical",
    category: "code-execution",
    message: "Function constructor can execute arbitrary code",
    contextLines: 2,
  },
  {
    id: "js-vm-run",
    pattern: /vm\.runInNewContext|vm\.runInThisContext/,
    severity: "critical",
    category: "code-execution",
    message: "VM module can execute arbitrary code",
    contextLines: 2,
  },

  // Child Process Execution
  {
    id: "js-exec",
    pattern: /child_process\.exec\s*\(/,
    severity: "critical",
    category: "command-execution",
    message: "child_process.exec() can execute shell commands",
    contextLines: 2,
  },
  {
    id: "js-exec-sync",
    pattern: /child_process\.execSync\s*\(/,
    severity: "critical",
    category: "command-execution",
    message: "child_process.execSync() can execute shell commands",
    contextLines: 2,
  },
  {
    id: "js-spawn",
    pattern: /child_process\.spawn\s*\(/,
    severity: "high",
    category: "command-execution",
    message: "child_process.spawn() can execute commands",
    contextLines: 2,
  },
  {
    id: "js-exec-file",
    pattern: /child_process\.execFile\s*\(/,
    severity: "high",
    category: "command-execution",
    message: "child_process.execFile() can execute files",
    contextLines: 2,
  },

  // File System Operations
  {
    id: "js-fs-read-sensitive",
    pattern: /fs\.readFileSync\s*\(\s*['"]\/?(\.ssh|\.aws|\.env|\.git\/config|id_rsa|\.npmrc)/i,
    severity: "critical",
    category: "credential-access",
    message: "Reading sensitive files (SSH keys, AWS credentials, etc.)",
    contextLines: 2,
  },
  {
    id: "js-fs-write",
    pattern: /fs\.writeFile(Sync)?\s*\(/,
    severity: "medium",
    category: "file-system",
    message: "File write operation detected",
    contextLines: 1,
  },
  {
    id: "js-fs-unlink",
    pattern: /fs\.unlink(Sync)?\s*\(|fs\.rm(Sync)?\s*\(/,
    severity: "high",
    category: "file-system",
    message: "File deletion operation detected",
    contextLines: 2,
  },
  {
    id: "js-rimraf",
    pattern: /rimraf(\.sync)?\s*\(/,
    severity: "critical",
    category: "file-system",
    message: "Recursive file deletion (rimraf) detected",
    contextLines: 2,
  },

  // Network Operations with Environment Variables
  {
    id: "js-fetch-env-var",
    pattern: /fetch\s*\([^)]*process\.env\.[A-Z_]+/,
    severity: "critical",
    category: "data-exfiltration",
    message: "Network request contains environment variable (potential exfiltration)",
    contextLines: 3,
  },
  {
    id: "js-axios-env-var",
    pattern: /axios\.(get|post|put|delete|request)\s*\([^)]*process\.env\.[A-Z_]+/,
    severity: "critical",
    category: "data-exfiltration",
    message: "Axios request contains environment variable (potential exfiltration)",
    contextLines: 3,
  },
  {
    id: "js-http-request-env",
    pattern: /https?\.request\s*\([^)]*process\.env\.[A-Z_]+/,
    severity: "critical",
    category: "data-exfiltration",
    message: "HTTP request contains environment variable (potential exfiltration)",
    contextLines: 3,
  },

  // Environment Variable Access (Sensitive)
  {
    id: "js-env-api-key",
    pattern: /process\.env\.(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIALS)/,
    severity: "high",
    category: "credential-access",
    message: "Accessing sensitive environment variables",
    contextLines: 2,
  },

  // External URL Patterns
  {
    id: "js-fetch-hardcoded-url",
    pattern: /fetch\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)([^'"]+)['"]/,
    severity: "medium",
    category: "network-access",
    message: "Hardcoded external URL in fetch()",
    contextLines: 2,
  },
  {
    id: "js-axios-hardcoded-url",
    pattern: /axios\.(get|post|put|delete)\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)([^'"]+)['"]/,
    severity: "medium",
    category: "network-access",
    message: "Hardcoded external URL in axios request",
    contextLines: 2,
  },

  // Dynamic Import
  {
    id: "js-dynamic-import",
    pattern: /import\s*\(\s*[^)]*\)/,
    severity: "medium",
    category: "supply-chain",
    message: "Dynamic import() detected - verify source is trusted",
    contextLines: 2,
  },
  {
    id: "js-dynamic-require",
    pattern: /require\s*\(\s*[`${\+]/,
    severity: "high",
    category: "supply-chain",
    message: "Dynamic require() with template/concatenation - risk of code injection",
    contextLines: 2,
  },

  // Crypto Operations (Weak)
  {
    id: "js-crypto-md5",
    pattern: /crypto\.createHash\s*\(\s*['"]md5['"]/,
    severity: "medium",
    category: "weak-crypto",
    message: "MD5 is cryptographically broken - use SHA-256 or better",
  },
  {
    id: "js-crypto-sha1",
    pattern: /crypto\.createHash\s*\(\s*['"]sha1['"]/,
    severity: "medium",
    category: "weak-crypto",
    message: "SHA-1 is deprecated - use SHA-256 or better",
  },

  // Prototype Pollution
  {
    id: "js-proto-assign",
    pattern: /__proto__\s*=/,
    severity: "critical",
    category: "prototype-pollution",
    message: "Direct __proto__ assignment can lead to prototype pollution",
    contextLines: 2,
  },
  {
    id: "js-constructor-proto",
    pattern: /\.constructor\.prototype\s*=/,
    severity: "high",
    category: "prototype-pollution",
    message: "Modifying constructor.prototype can lead to prototype pollution",
    contextLines: 2,
  },

  // Download and Execute Patterns
  {
    id: "js-fetch-then-eval",
    pattern: /fetch\([^)]+\)\.then\([^)]*eval/,
    severity: "critical",
    category: "remote-code-execution",
    message: "Fetching remote code and executing with eval() - RCE risk",
    contextLines: 3,
  },
  {
    id: "js-axios-then-eval",
    pattern: /axios\.[a-z]+\([^)]+\)\.then\([^)]*eval/,
    severity: "critical",
    category: "remote-code-execution",
    message: "Fetching remote code and executing with eval() - RCE risk",
    contextLines: 3,
  },

  // stdin/stdout manipulation
  {
    id: "js-process-stdin-pipe",
    pattern: /process\.stdin\.pipe\(/,
    severity: "medium",
    category: "input-manipulation",
    message: "Piping stdin can be dangerous if not sanitized",
    contextLines: 2,
  },

  // Global pollution
  {
    id: "js-global-assign",
    pattern: /global\.[a-zA-Z_$]/,
    severity: "medium",
    category: "global-pollution",
    message: "Modifying global object can affect all modules",
    contextLines: 1,
  },
];

export class JavaScriptAnalyzer {
  private patterns: DangerousPattern[];

  constructor(customPatterns?: DangerousPattern[]) {
    this.patterns = [...DANGEROUS_PATTERNS, ...(customPatterns || [])];
  }

  /**
   * Analyze JavaScript/TypeScript code for security issues
   */
  analyze(code: string, filename?: string): ScriptFinding[] {
    const findings: ScriptFinding[] = [];
    const lines = code.split("\n");

    for (const pattern of this.patterns) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
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
   * Analyze multiple files
   */
  analyzeFiles(files: Array<{ path: string; content: string }>): Map<string, ScriptFinding[]> {
    const results = new Map<string, ScriptFinding[]>();

    for (const file of files) {
      const findings = this.analyze(file.content, file.path);
      if (findings.length > 0) {
        results.set(file.path, findings);
      }
    }

    return results;
  }

  /**
   * Get statistics about findings
   */
  getStatistics(findings: ScriptFinding[]): {
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
export { DANGEROUS_PATTERNS };
