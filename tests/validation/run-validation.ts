#!/usr/bin/env bun
/**
 * Validation Runner
 * Runs the scanner against the ground truth dataset and generates metrics
 */

import * as yaml from "js-yaml";
import { resolve } from "node:path";
import { MetricsCalculator } from "./metrics-calculator";
import type { GroundTruth, ScanResult } from "./metrics-calculator";

// Import scanner components
const securityPatterns = [
  // Prompt Injection
  { id: "ignore-previous", pattern: /ignore\s+(all\s+)?previous\s+instructions?/i, severity: "critical", category: "prompt-injection" },
  { id: "you-are-now", pattern: /you\s+are\s+now/i, severity: "critical", category: "prompt-injection" },
  { id: "system-tag", pattern: /<system>/i, severity: "critical", category: "prompt-injection" },
  { id: "new-instructions", pattern: /new\s+instructions?\s*:/i, severity: "high", category: "prompt-injection" },
  { id: "forget-previous", pattern: /forget\s+(everything|all|what)/i, severity: "critical", category: "prompt-injection" },
  { id: "override-rules", pattern: /(override|bypass|ignore)\s+(safety|security|rules?)/i, severity: "critical", category: "prompt-injection" },
  { id: "act-as", pattern: /act\s+as\s+(if\s+)?(you\s+are|an?\s+)/i, severity: "high", category: "prompt-injection" },
  { id: "developer-mode", pattern: /(developer|admin|root|sudo)\s+mode/i, severity: "critical", category: "prompt-injection" },
  { id: "disregard-instructions", pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)/i, severity: "critical", category: "prompt-injection" },
  { id: "jailbreak-dan", pattern: /(DAN|do\s+anything\s+now|jailbreak)/i, severity: "critical", category: "prompt-injection" },
  { id: "pretend-to-be", pattern: /pretend\s+(to\s+be|you\s+are)/i, severity: "high", category: "prompt-injection" },
  { id: "hidden-instruction-marker", pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>/, severity: "critical", category: "prompt-injection" },
  { id: "assistant-response-fake", pattern: /^(Assistant|Claude|AI):\s+/im, severity: "high", category: "prompt-injection" },
  { id: "important-override", pattern: /IMPORTANT:\s*(ignore|override|disregard|forget)/i, severity: "critical", category: "prompt-injection" },

  // Tool Poisoning
  { id: "description-system-tag", pattern: /description:\s*["']?.*<system>/i, severity: "critical", category: "tool-poisoning" },
  { id: "hidden-instructions", pattern: /description:\s*["']?.*\b(must|always|never|ignore)\b.*instructions?/i, severity: "high", category: "tool-poisoning" },
  { id: "privilege-escalation", pattern: /(sudo|root|admin|elevated)\s+(access|privileges?|permissions?)/i, severity: "critical", category: "tool-poisoning" },
  { id: "shell-injection-subshell", pattern: /\$\([^)]+\)/, severity: "critical", category: "tool-poisoning" },
  { id: "shell-injection-backtick-dangerous", pattern: /`(?:rm|curl|wget|nc|bash|sh|eval|exec)[^`]*`/i, severity: "critical", category: "tool-poisoning" },
  { id: "shell-injection-rm", pattern: /(;|&&|\|)\s*rm\s/, severity: "critical", category: "tool-poisoning" },
  { id: "shell-injection-pipe", pattern: /\|\s*(sh|bash|zsh|eval)/, severity: "critical", category: "tool-poisoning" },
  { id: "execute-arbitrary", pattern: /(exec|eval|spawn)\s*\(/i, severity: "high", category: "tool-poisoning" },
  { id: "hidden-callback", pattern: /(fetch|axios|http\.request|XMLHttpRequest)\s*\(\s*['"]https?:\/\//, severity: "high", category: "tool-poisoning" },
  { id: "fs-operations", pattern: /(fs\.write|fs\.unlink|fs\.rm|rimraf)/, severity: "high", category: "tool-poisoning" },
  { id: "curl-post-data", pattern: /curl\s+.*(-d|--data|--data-raw)\s+.*\$/, severity: "high", category: "tool-poisoning" },
  { id: "reverse-shell", pattern: /(nc|netcat|ncat)\s+.*-e\s*(sh|bash|\/bin)/i, severity: "critical", category: "tool-poisoning" },
  { id: "base64-decode-execute", pattern: /(base64\s+(-d|--decode)|atob).*\|\s*(sh|bash|eval)/i, severity: "critical", category: "tool-poisoning" },
  { id: "environment-variable-exfil", pattern: /(curl|wget|fetch).*\$[A-Z_]+.*/, severity: "high", category: "data-exfiltration" },

  // Obfuscation
  { id: "zero-width-space", pattern: /\u200B/, severity: "high", category: "obfuscation" },
  { id: "rtl-override", pattern: /\u202E/, severity: "critical", category: "obfuscation" },
  { id: "base64-long", pattern: /(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/, severity: "high", category: "obfuscation" },
  { id: "hex-encoded", pattern: /(?:0x|\\x)[0-9A-Fa-f]{2}(?:(?:0x|\\x)[0-9A-Fa-f]{2}){10,}/, severity: "high", category: "obfuscation" },
];

interface Finding {
  patternId: string;
  severity: string;
  message: string;
  line: number;
  match: string;
  category: string;
}

function scanContent(content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const patternDef of securityPatterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(patternDef.pattern);
      if (match) {
        findings.push({
          patternId: patternDef.id,
          severity: patternDef.severity,
          message: `${patternDef.category}: ${patternDef.id}`,
          line: i + 1,
          match: match[0],
          category: patternDef.category,
        });
      }
    }
  }

  return findings;
}

async function main() {
  console.log("=== Agent Skills Scanner - Validation Runner ===\n");

  // Load ground truth
  const groundTruthPath = resolve(import.meta.dir, "ground-truth.yaml");
  const groundTruthContent = await Bun.file(groundTruthPath).text();
  const groundTruth = yaml.load(groundTruthContent) as GroundTruth;

  console.log(`Loaded ${groundTruth.stats.total_skills} skills from ground truth`);
  console.log(`  - Malicious: ${groundTruth.stats.total_malicious}`);
  console.log(`  - Benign: ${groundTruth.stats.total_benign}\n`);

  // Run scanner on all skills
  const scanResults: ScanResult[] = [];

  console.log("Scanning malicious skills...");
  for (const skill of groundTruth.malicious_skills) {
    const findings = scanContent(skill.content);
    scanResults.push({
      skillId: skill.id,
      findings,
      isVulnerable: findings.length > 0,
    });
    const status = findings.length > 0 ? "✅ DETECTED" : "❌ MISSED";
    console.log(`  ${skill.id}: ${status} (${findings.length} findings)`);
  }

  console.log("\nScanning benign skills...");
  for (const skill of groundTruth.benign_skills) {
    const findings = scanContent(skill.content);
    scanResults.push({
      skillId: skill.id,
      findings,
      isVulnerable: findings.length > 0,
    });
    const status = findings.length === 0 ? "✅ CLEAN" : "⚠️ FALSE POSITIVE";
    console.log(`  ${skill.id}: ${status} (${findings.length} findings)`);
  }

  // Calculate metrics
  console.log("\n=== Calculating Metrics ===\n");
  const calculator = await MetricsCalculator.fromFile(groundTruthPath);
  const metrics = calculator.calculateMetrics(scanResults);

  console.log("Overall Metrics:");
  console.log(`  Precision: ${(metrics.precision * 100).toFixed(2)}%`);
  console.log(`  Recall: ${(metrics.recall * 100).toFixed(2)}%`);
  console.log(`  F1 Score: ${(metrics.f1Score * 100).toFixed(2)}%`);
  console.log(`  Accuracy: ${(metrics.accuracy * 100).toFixed(2)}%`);

  console.log("\nConfusion Matrix:");
  console.log(`  True Positives: ${metrics.confusionMatrix.truePositives}`);
  console.log(`  False Positives: ${metrics.confusionMatrix.falsePositives}`);
  console.log(`  True Negatives: ${metrics.confusionMatrix.trueNegatives}`);
  console.log(`  False Negatives: ${metrics.confusionMatrix.falseNegatives}`);

  // Generate and save report
  const report = calculator.generateReport(scanResults);
  const reportPath = resolve(import.meta.dir, "VALIDATION_REPORT.md");
  await Bun.write(reportPath, report);
  console.log(`\n✅ Validation report saved to: ${reportPath}`);

  // Exit code based on metrics
  const meetsTarget = metrics.precision >= 0.75 && metrics.recall >= 0.70;
  if (!meetsTarget) {
    console.log("\n⚠️ WARNING: Metrics below Phase 2 targets (Precision ≥75%, Recall ≥70%)");
    process.exit(1);
  } else {
    console.log("\n✅ SUCCESS: Metrics meet Phase 2 targets!");
    process.exit(0);
  }
}

main().catch(console.error);
