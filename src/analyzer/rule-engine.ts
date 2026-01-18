import * as yaml from "js-yaml";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import type { ParsedSkill } from "../parser/skill-parser";
import { matchPattern, type Pattern, type PatternMatch } from "./pattern-matcher";

export interface Rule {
  id: string;
  name: string;
  description: string;
  priority: string;
  patterns: Pattern[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  patternId: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  filePath: string;
  line: number;
  column: number;
  endColumn: number;
  match: string;
  priority: string;
}

export class RuleEngine {
  private rules: Rule[] = [];

  async loadRules(rulesDir: string): Promise<void> {
    const files = await readdir(rulesDir);
    const yamlFiles = files.filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));

    for (const file of yamlFiles) {
      const content = await Bun.file(join(rulesDir, file)).text();
      const rule = yaml.load(content) as Rule;
      this.rules.push(rule);
    }
  }

  analyze(parsedSkill: ParsedSkill): Finding[] {
    const findings: Finding[] = [];

    for (const rule of this.rules) {
      for (const pattern of rule.patterns) {
        const matches = matchPattern(parsedSkill.rawContent, rule.id, pattern);

        for (const match of matches) {
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            patternId: match.patternId,
            message: match.message,
            severity: match.severity,
            filePath: parsedSkill.filePath,
            line: match.line,
            column: match.column,
            endColumn: match.endColumn,
            match: match.match,
            priority: rule.priority,
          });
        }
      }
    }

    // Sort by severity (critical > high > medium > low)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return findings;
  }

  getRules(): Rule[] {
    return this.rules;
  }
}
