/**
 * Supply Chain Analyzer - Main Entry Point
 * Analyzes dependencies, external resources, and supply chain risks
 */

import { DependencyAnalyzer, type DependencyFinding } from "./dependency-analyzer";

export interface SupplyChainAnalysisResult {
  findings: DependencyFinding[];
  statistics: {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
  };
  riskScore: number;  // 0-100, higher is riskier
}

export class SupplyChainAnalyzer {
  private dependencyAnalyzer: DependencyAnalyzer;

  constructor() {
    this.dependencyAnalyzer = new DependencyAnalyzer();
  }

  /**
   * Analyze a skill package for supply chain risks
   */
  analyzeSkillPackage(files: Array<{ path: string; content: string }>): SupplyChainAnalysisResult {
    const allFindings: DependencyFinding[] = [];

    for (const file of files) {
      const fileName = file.path.toLowerCase();

      // Analyze package.json
      if (fileName.endsWith("package.json")) {
        const findings = this.dependencyAnalyzer.analyzePackageJson(file.content);
        allFindings.push(...findings);
      }

      // Analyze requirements.txt
      if (fileName.endsWith("requirements.txt")) {
        const findings = this.dependencyAnalyzer.analyzeRequirementsTxt(file.content);
        allFindings.push(...findings);
      }

      // Analyze JavaScript/TypeScript files for dynamic imports
      if (/\.(js|jsx|ts|tsx|mjs)$/i.test(fileName)) {
        const findings = this.dependencyAnalyzer.analyzeDynamicImports(file.content, "javascript");
        allFindings.push(...findings);
      }

      // Analyze Python files for dynamic imports
      if (/\.py$/i.test(fileName)) {
        const findings = this.dependencyAnalyzer.analyzeDynamicImports(file.content, "python");
        allFindings.push(...findings);
      }
    }

    const statistics = this.dependencyAnalyzer.getStatistics(allFindings);
    const riskScore = this.calculateRiskScore(allFindings);

    return {
      findings: allFindings,
      statistics,
      riskScore,
    };
  }

  /**
   * Calculate overall risk score (0-100)
   */
  private calculateRiskScore(findings: DependencyFinding[]): number {
    let score = 0;

    const severityWeights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
    };

    for (const finding of findings) {
      score += severityWeights[finding.severity] || 0;
    }

    // Cap at 100
    return Math.min(100, score);
  }

  /**
   * Get risk level based on score
   */
  getRiskLevel(score: number): "critical" | "high" | "medium" | "low" {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    return "low";
  }
}

// Re-export types
export { DependencyAnalyzer, type DependencyFinding } from "./dependency-analyzer";
