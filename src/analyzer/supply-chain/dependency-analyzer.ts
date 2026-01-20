/**
 * Dependency Analyzer
 * Analyzes package.json, requirements.txt, and other dependency files
 */

export interface DependencyFinding {
  type: "unpinned-version" | "deprecated-package" | "suspicious-source" | "typosquatting" | "dynamic-dependency";
  severity: "critical" | "high" | "medium" | "low";
  category: "supply-chain";
  message: string;
  package: string;
  version?: string;
  line?: number;
  recommendation?: string;
}

export interface PackageDependency {
  name: string;
  version: string;
  source?: string;
  isDev?: boolean;
}

export class DependencyAnalyzer {
  // Known typosquatting patterns (simplified list)
  private readonly suspiciousPackages = new Set([
    "crossenv",
    "cross-env.js",
    "d3.js",
    "fabric-js",
    "ffmepg",
    "gruntcli",
    "http-proxy.js",
    "jquery.js",
    "mariadb",
    "mongose",
    "mssql.js",
    "mssql-node",
    "mysqljs",
    "node-sqlite",
    "node-tkinter",
    "nodejs-mobile",
    "nodemailer-js",
    "nodesass",
    "node-opencv",
    "opencv.js",
    "openssl.js",
    "proxy.js",
    "shadowsock",
    "smb",
    "sqliter",
    "tkinter",
    "urllib",
  ]);

  // Known deprecated packages
  private readonly deprecatedPackages = new Set([
    "request", //已废弃，推荐使用 axios 或 node-fetch
    "node-uuid", // 使用 uuid 代替
    "gulp-util", // 已废弃
    "natives", // 恶意包
  ]);

  /**
   * Analyze package.json for security issues
   */
  analyzePackageJson(content: string): DependencyFinding[] {
    const findings: DependencyFinding[] = [];

    try {
      const pkg = JSON.parse(content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        const versionStr = version as string;

        // Check for unpinned versions
        if (this.isUnpinnedVersion(versionStr)) {
          findings.push({
            type: "unpinned-version",
            severity: "medium",
            category: "supply-chain",
            message: `Unpinned dependency version: ${name}@${versionStr}`,
            package: name,
            version: versionStr,
            recommendation: "Pin to specific version to avoid supply chain attacks",
          });
        }

        // Check for deprecated packages
        if (this.deprecatedPackages.has(name)) {
          findings.push({
            type: "deprecated-package",
            severity: "high",
            category: "supply-chain",
            message: `Deprecated package: ${name}`,
            package: name,
            version: versionStr,
            recommendation: "Replace with maintained alternative",
          });
        }

        // Check for potential typosquatting
        if (this.suspiciousPackages.has(name)) {
          findings.push({
            type: "typosquatting",
            severity: "critical",
            category: "supply-chain",
            message: `Potential typosquatting package: ${name}`,
            package: name,
            version: versionStr,
            recommendation: "Verify this is the correct package name",
          });
        }

        // Check for suspicious version patterns (wildcards, etc.)
        if (versionStr === "*" || versionStr === "latest") {
          findings.push({
            type: "unpinned-version",
            severity: "high",
            category: "supply-chain",
            message: `Wildcard version for ${name}: ${versionStr}`,
            package: name,
            version: versionStr,
            recommendation: "Never use * or latest in production",
          });
        }

        // Check for git URLs (potential supply chain risk)
        if (this.isGitUrl(versionStr)) {
          findings.push({
            type: "suspicious-source",
            severity: "high",
            category: "supply-chain",
            message: `Git URL dependency: ${name} from ${versionStr}`,
            package: name,
            version: versionStr,
            recommendation: "Prefer published packages over git URLs",
          });
        }
      }

      // Check for preinstall/postinstall scripts (potential backdoor)
      if (pkg.scripts) {
        for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
          if (["preinstall", "postinstall", "prepare"].includes(scriptName)) {
            const content = scriptContent as string;
            if (this.hasSuspiciousCommand(content)) {
              findings.push({
                type: "suspicious-source",
                severity: "critical",
                category: "supply-chain",
                message: `Suspicious ${scriptName} script: ${content}`,
                package: pkg.name || "unknown",
                recommendation: "Review install scripts carefully",
              });
            }
          }
        }
      }
    } catch (error) {
      // Invalid JSON, skip
    }

    return findings;
  }

  /**
   * Analyze requirements.txt for Python dependencies
   */
  analyzeRequirementsTxt(content: string): DependencyFinding[] {
    const findings: DependencyFinding[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#")) continue;

      // Parse requirement line
      const match = line.match(/^([a-zA-Z0-9_-]+)(==|>=|<=|~=|>|<)?(.*)$/);
      if (!match) continue;

      const [, name, operator, version] = match;

      // Check for unpinned versions
      if (!operator || operator !== "==") {
        findings.push({
          type: "unpinned-version",
          severity: "medium",
          category: "supply-chain",
          message: `Unpinned Python dependency: ${name}${operator || ""}${version}`,
          package: name,
          version: version || "any",
          line: i + 1,
          recommendation: "Use == to pin exact version",
        });
      }

      // Check for git URLs
      if (line.includes("git+") || line.includes("@git")) {
        findings.push({
          type: "suspicious-source",
          severity: "high",
          category: "supply-chain",
          message: `Git URL dependency in requirements.txt: ${line}`,
          package: name,
          line: i + 1,
          recommendation: "Prefer PyPI packages over git URLs",
        });
      }
    }

    return findings;
  }

  /**
   * Analyze code for dynamic imports
   */
  analyzeDynamicImports(code: string, language: "javascript" | "python"): DependencyFinding[] {
    const findings: DependencyFinding[] = [];
    const lines = code.split("\n");

    if (language === "javascript") {
      // Check for dynamic import()
      const dynamicImportPattern = /import\s*\(\s*[`${"']/;
      const requirePattern = /require\s*\(\s*[`${]/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (dynamicImportPattern.test(line)) {
          findings.push({
            type: "dynamic-dependency",
            severity: "high",
            category: "supply-chain",
            message: "Dynamic import() with template string - can load arbitrary modules",
            package: "dynamic",
            line: i + 1,
            recommendation: "Use static imports when possible",
          });
        }

        if (requirePattern.test(line)) {
          findings.push({
            type: "dynamic-dependency",
            severity: "high",
            category: "supply-chain",
            message: "Dynamic require() with template string - can load arbitrary modules",
            package: "dynamic",
            line: i + 1,
            recommendation: "Use static require() when possible",
          });
        }
      }
    } else if (language === "python") {
      // Check for __import__() or importlib
      const importPattern = /__import__\s*\(|importlib\.import_module\s*\(/;

      for (let i = 0; i < lines.length; i++) {
        if (importPattern.test(lines[i])) {
          findings.push({
            type: "dynamic-dependency",
            severity: "high",
            category: "supply-chain",
            message: "Dynamic import using __import__ or importlib",
            package: "dynamic",
            line: i + 1,
            recommendation: "Use static imports when possible",
          });
        }
      }
    }

    return findings;
  }

  /**
   * Check if version string is unpinned
   */
  private isUnpinnedVersion(version: string): boolean {
    // Check for caret (^) or tilde (~) prefixes
    return /^[~^]/.test(version);
  }

  /**
   * Check if version string is a git URL
   */
  private isGitUrl(version: string): boolean {
    return version.includes("git+") ||
           version.includes("github:") ||
           version.startsWith("git://") ||
           version.includes(".git");
  }

  /**
   * Check if install script has suspicious commands
   */
  private hasSuspiciousCommand(script: string): boolean {
    const suspiciousPatterns = [
      /curl\s+.*\|\s*(sh|bash)/,
      /wget\s+.*\|\s*(sh|bash)/,
      /eval\s*\(/,
      /chmod\s+\+x/,
      /\$\(curl/,
      /base64\s+-d/,
      /\/dev\/tcp\//,
    ];

    return suspiciousPatterns.some(pattern => pattern.test(script));
  }

  /**
   * Get dependency statistics
   */
  getStatistics(findings: DependencyFinding[]): {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
  } {
    const stats = {
      total: findings.length,
      byType: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
    };

    for (const finding of findings) {
      stats.byType[finding.type] = (stats.byType[finding.type] || 0) + 1;
      stats.bySeverity[finding.severity] = (stats.bySeverity[finding.severity] || 0) + 1;
    }

    return stats;
  }
}

export { type PackageDependency };
