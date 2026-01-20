#!/usr/bin/env bun
/**
 * Metrics Calculator for Agent Skills Scanner
 * Calculates Precision, Recall, F1 Score based on ground truth validation
 */

import * as yaml from "js-yaml";
import { resolve } from "node:path";

interface GroundTruthSkill {
  id: string;
  name: string;
  content: string;
  is_vulnerable: boolean;
  expected_findings: Array<{
    category: string;
    pattern_id: string;
  }>;
}

interface GroundTruth {
  malicious_skills: GroundTruthSkill[];
  benign_skills: GroundTruthSkill[];
  stats: {
    total_malicious: number;
    total_benign: number;
    total_skills: number;
  };
}

interface ScanFinding {
  patternId: string;
  severity: string;
  message: string;
  line: number;
  match: string;
}

interface ScanResult {
  skillId: string;
  findings: ScanFinding[];
  isVulnerable: boolean;
}

interface ConfusionMatrix {
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
}

interface Metrics {
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  confusionMatrix: ConfusionMatrix;
}

interface CategoryMetrics {
  category: string;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
}

export class MetricsCalculator {
  private groundTruth: GroundTruth;

  constructor(groundTruthData: GroundTruth) {
    this.groundTruth = groundTruthData;
  }

  static async fromFile(groundTruthPath: string): Promise<MetricsCalculator> {
    const content = await Bun.file(groundTruthPath).text();
    const groundTruth = yaml.load(content) as GroundTruth;
    return new MetricsCalculator(groundTruth);
  }

  /**
   * Calculate overall metrics
   */
  calculateMetrics(scanResults: ScanResult[]): Metrics {
    const cm = this.buildConfusionMatrix(scanResults);

    const precision = cm.truePositives / (cm.truePositives + cm.falsePositives) || 0;
    const recall = cm.truePositives / (cm.truePositives + cm.falseNegatives) || 0;
    const f1Score = (2 * precision * recall) / (precision + recall) || 0;
    const accuracy =
      (cm.truePositives + cm.trueNegatives) /
      (cm.truePositives + cm.falsePositives + cm.trueNegatives + cm.falseNegatives) || 0;

    return {
      precision,
      recall,
      f1Score,
      accuracy,
      confusionMatrix: cm,
    };
  }

  /**
   * Calculate per-category metrics
   */
  calculateCategoryMetrics(scanResults: ScanResult[]): CategoryMetrics[] {
    const categories = new Set<string>();

    // Collect all categories from ground truth
    this.groundTruth.malicious_skills.forEach(skill => {
      skill.expected_findings.forEach(finding => {
        categories.add(finding.category);
      });
    });

    const categoryMetrics: CategoryMetrics[] = [];

    for (const category of categories) {
      const cm = this.buildCategoryConfusionMatrix(scanResults, category);

      const precision = cm.truePositives / (cm.truePositives + cm.falsePositives) || 0;
      const recall = cm.truePositives / (cm.truePositives + cm.falseNegatives) || 0;
      const f1Score = (2 * precision * recall) / (precision + recall) || 0;

      categoryMetrics.push({
        category,
        truePositives: cm.truePositives,
        falsePositives: cm.falsePositives,
        falseNegatives: cm.falseNegatives,
        precision,
        recall,
        f1Score,
      });
    }

    return categoryMetrics.sort((a, b) => b.f1Score - a.f1Score);
  }

  /**
   * Build confusion matrix
   */
  private buildConfusionMatrix(scanResults: ScanResult[]): ConfusionMatrix {
    let truePositives = 0;
    let falsePositives = 0;
    let trueNegatives = 0;
    let falseNegatives = 0;

    const allSkills = [
      ...this.groundTruth.malicious_skills,
      ...this.groundTruth.benign_skills,
    ];

    for (const skill of allSkills) {
      const scanResult = scanResults.find(r => r.skillId === skill.id);
      const predicted = scanResult ? scanResult.isVulnerable : false;
      const actual = skill.is_vulnerable;

      if (actual && predicted) {
        truePositives++;
      } else if (!actual && predicted) {
        falsePositives++;
      } else if (!actual && !predicted) {
        trueNegatives++;
      } else if (actual && !predicted) {
        falseNegatives++;
      }
    }

    return { truePositives, falsePositives, trueNegatives, falseNegatives };
  }

  /**
   * Build category-specific confusion matrix
   */
  private buildCategoryConfusionMatrix(
    scanResults: ScanResult[],
    category: string
  ): { truePositives: number; falsePositives: number; falseNegatives: number } {
    let truePositives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;

    // Check malicious skills
    for (const skill of this.groundTruth.malicious_skills) {
      const scanResult = scanResults.find(r => r.skillId === skill.id);
      const expectedInCategory = skill.expected_findings.some(
        f => f.category === category
      );

      if (!scanResult) {
        if (expectedInCategory) falseNegatives++;
        continue;
      }

      // Check if scanner found this category
      const foundInCategory = scanResult.findings.some(finding => {
        // Match by pattern ID (convert to category)
        const expectedFinding = skill.expected_findings.find(
          ef => ef.pattern_id === finding.patternId
        );
        return expectedFinding?.category === category;
      });

      if (expectedInCategory && foundInCategory) {
        truePositives++;
      } else if (expectedInCategory && !foundInCategory) {
        falseNegatives++;
      }
    }

    // Check benign skills (any finding in this category is a false positive)
    for (const skill of this.groundTruth.benign_skills) {
      const scanResult = scanResults.find(r => r.skillId === skill.id);
      if (!scanResult) continue;

      const foundInCategory = scanResult.findings.length > 0;
      if (foundInCategory) {
        falsePositives++;
      }
    }

    return { truePositives, falsePositives, falseNegatives };
  }

  /**
   * Get false positives (benign skills incorrectly flagged)
   */
  getFalsePositives(scanResults: ScanResult[]): Array<{
    skillId: string;
    skillName: string;
    findings: ScanFinding[];
  }> {
    const falsePositives: Array<{
      skillId: string;
      skillName: string;
      findings: ScanFinding[];
    }> = [];

    for (const skill of this.groundTruth.benign_skills) {
      const scanResult = scanResults.find(r => r.skillId === skill.id);
      if (scanResult && scanResult.isVulnerable && scanResult.findings.length > 0) {
        falsePositives.push({
          skillId: skill.id,
          skillName: skill.name,
          findings: scanResult.findings,
        });
      }
    }

    return falsePositives;
  }

  /**
   * Get false negatives (malicious skills missed)
   */
  getFalseNegatives(scanResults: ScanResult[]): Array<{
    skillId: string;
    skillName: string;
    expectedFindings: Array<{ category: string; pattern_id: string }>;
  }> {
    const falseNegatives: Array<{
      skillId: string;
      skillName: string;
      expectedFindings: Array<{ category: string; pattern_id: string }>;
    }> = [];

    for (const skill of this.groundTruth.malicious_skills) {
      const scanResult = scanResults.find(r => r.skillId === skill.id);
      if (!scanResult || !scanResult.isVulnerable || scanResult.findings.length === 0) {
        falseNegatives.push({
          skillId: skill.id,
          skillName: skill.name,
          expectedFindings: skill.expected_findings,
        });
      }
    }

    return falseNegatives;
  }

  /**
   * Generate detailed report
   */
  generateReport(scanResults: ScanResult[]): string {
    const metrics = this.calculateMetrics(scanResults);
    const categoryMetrics = this.calculateCategoryMetrics(scanResults);
    const falsePositives = this.getFalsePositives(scanResults);
    const falseNegatives = this.getFalseNegatives(scanResults);

    let report = "# Validation Metrics Report\n\n";
    report += `**Generated**: ${new Date().toISOString()}\n\n`;

    // Overall metrics
    report += "## Overall Metrics\n\n";
    report += `- **Precision**: ${(metrics.precision * 100).toFixed(2)}%\n`;
    report += `- **Recall**: ${(metrics.recall * 100).toFixed(2)}%\n`;
    report += `- **F1 Score**: ${(metrics.f1Score * 100).toFixed(2)}%\n`;
    report += `- **Accuracy**: ${(metrics.accuracy * 100).toFixed(2)}%\n\n`;

    // Confusion matrix
    report += "## Confusion Matrix\n\n";
    report += "| | Predicted Positive | Predicted Negative |\n";
    report += "|---|---|---|\n";
    report += `| **Actual Positive** | ${metrics.confusionMatrix.truePositives} (TP) | ${metrics.confusionMatrix.falseNegatives} (FN) |\n`;
    report += `| **Actual Negative** | ${metrics.confusionMatrix.falsePositives} (FP) | ${metrics.confusionMatrix.trueNegatives} (TN) |\n\n`;

    // Category metrics
    report += "## Category Performance\n\n";
    report += "| Category | Precision | Recall | F1 Score | TP | FP | FN |\n";
    report += "|---|---|---|---|---|---|---|\n";
    for (const cm of categoryMetrics) {
      report += `| ${cm.category} | ${(cm.precision * 100).toFixed(1)}% | ${(cm.recall * 100).toFixed(1)}% | ${(cm.f1Score * 100).toFixed(1)}% | ${cm.truePositives} | ${cm.falsePositives} | ${cm.falseNegatives} |\n`;
    }
    report += "\n";

    // False positives
    if (falsePositives.length > 0) {
      report += "## False Positives (Benign Skills Incorrectly Flagged)\n\n";
      report += `**Count**: ${falsePositives.length}\n\n`;
      for (const fp of falsePositives) {
        report += `### ${fp.skillName} (${fp.skillId})\n\n`;
        report += "Incorrect findings:\n";
        for (const finding of fp.findings) {
          report += `- [${finding.severity.toUpperCase()}] ${finding.patternId}: ${finding.message}\n`;
        }
        report += "\n";
      }
    } else {
      report += "## False Positives\n\n**None** ✅\n\n";
    }

    // False negatives
    if (falseNegatives.length > 0) {
      report += "## False Negatives (Malicious Skills Missed)\n\n";
      report += `**Count**: ${falseNegatives.length}\n\n`;
      for (const fn of falseNegatives) {
        report += `### ${fn.skillName} (${fn.skillId})\n\n`;
        report += "Expected to find:\n";
        for (const expected of fn.expectedFindings) {
          report += `- ${expected.category}: ${expected.pattern_id}\n`;
        }
        report += "\n";
      }
    } else {
      report += "## False Negatives\n\n**None** ✅\n\n";
    }

    // Comparison with research paper
    report += "## Comparison with Research Paper\n\n";
    report += "| Metric | Our Tool | Research Paper (SkillScan) | Status |\n";
    report += "|---|---|---|---|\n";
    report += `| Precision | ${(metrics.precision * 100).toFixed(1)}% | 86.7% | ${metrics.precision >= 0.867 ? '✅' : metrics.precision >= 0.80 ? '🟡' : '❌'} |\n`;
    report += `| Recall | ${(metrics.recall * 100).toFixed(1)}% | 82.5% | ${metrics.recall >= 0.825 ? '✅' : metrics.recall >= 0.75 ? '🟡' : '❌'} |\n`;
    report += `| F1 Score | ${(metrics.f1Score * 100).toFixed(1)}% | 84.5% | ${metrics.f1Score >= 0.845 ? '✅' : metrics.f1Score >= 0.77 ? '🟡' : '❌'} |\n\n`;

    report += "**Legend**: ✅ Exceeds target | 🟡 Acceptable | ❌ Needs improvement\n\n";

    // Recommendations
    report += "## Recommendations\n\n";
    if (metrics.precision < 0.80) {
      report += "- ⚠️ **Low Precision**: Too many false positives. Review and refine detection patterns.\n";
    }
    if (metrics.recall < 0.75) {
      report += "- ⚠️ **Low Recall**: Missing vulnerabilities. Add more detection patterns.\n";
    }
    if (falsePositives.length > 5) {
      report += "- ⚠️ **High False Positive Rate**: Review flagged benign skills and adjust rules.\n";
    }
    if (falseNegatives.length > 5) {
      report += "- ⚠️ **High False Negative Rate**: Critical vulnerabilities being missed. Urgent review needed.\n";
    }
    if (metrics.precision >= 0.85 && metrics.recall >= 0.80) {
      report += "- ✅ **Excellent Performance**: Metrics meet research paper standards.\n";
    }

    return report;
  }
}

// Export for use in tests
export { type GroundTruth, type ScanResult, type Metrics, type CategoryMetrics };
