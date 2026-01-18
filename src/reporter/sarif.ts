import type { Finding } from "../analyzer/rule-engine";
import type { Rule } from "../analyzer/rule-engine";

interface SarifLevel {
  critical: "error";
  high: "error";
  medium: "warning";
  low: "note";
}

const SARIF_LEVEL: SarifLevel = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        startColumn: number;
        endColumn: number;
      };
    };
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties: { priority: string };
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

export function generateSarifReport(findings: Finding[], rules: Rule[]): SarifReport {
  const ruleMap = new Map<string, number>();
  const sarifRules: SarifRule[] = [];

  // Build rule definitions from loaded rules
  for (const rule of rules) {
    const ruleIndex = sarifRules.length;
    ruleMap.set(rule.id, ruleIndex);
    sarifRules.push({
      id: rule.id,
      name: rule.name,
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.description },
      defaultConfiguration: { level: "warning" },
      properties: { priority: rule.priority },
    });
  }

  const results: SarifResult[] = findings.map((finding) => {
    const ruleIndex = ruleMap.get(finding.ruleId) ?? 0;

    return {
      ruleId: `${finding.ruleId}/${finding.patternId}`,
      ruleIndex,
      level: SARIF_LEVEL[finding.severity],
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.filePath },
            region: {
              startLine: finding.line,
              startColumn: finding.column,
              endColumn: finding.endColumn,
            },
          },
        },
      ],
    };
  });

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agent-skills-scanner",
            version: "0.1.0",
            informationUri: "https://github.com/HikaruEgashira/agent-skills-scanner",
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };
}

export function formatSarifReport(findings: Finding[], rules: Rule[]): string {
  const report = generateSarifReport(findings, rules);
  return JSON.stringify(report, null, 2);
}
