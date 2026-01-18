#!/usr/bin/env bun
import { resolve, dirname } from "node:path";
import { parseSkillFile } from "../parser/skill-parser";
import { RuleEngine } from "../analyzer/rule-engine";
import { printConsoleReport } from "../reporter/console";
import { formatSarifReport } from "../reporter/sarif";

interface CliOptions {
  format: "console" | "sarif";
  rulesDir: string;
}

function printUsage(): void {
  console.log(`
agent-skills-scanner - Security scanner for SKILL.md files

Usage:
  bun run scan <file> [options]
  skill-scan <file> [options]

Options:
  --format <console|sarif>  Output format (default: console)
  --rules <dir>             Custom rules directory
  --help                    Show this help message

Examples:
  bun run scan ./SKILL.md
  bun run scan ./SKILL.md --format sarif > report.sarif
  bun run scan ./skills/*.md --rules ./custom-rules
`);
}

function parseArgs(args: string[]): { files: string[]; options: CliOptions } {
  const files: string[] = [];
  const options: CliOptions = {
    format: "console",
    rulesDir: resolve(dirname(import.meta.path), "../../rules"),
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else if (arg === "--format") {
      const format = args[++i];
      if (format === "console" || format === "sarif") {
        options.format = format;
      } else {
        console.error(`Invalid format: ${format}. Use 'console' or 'sarif'.`);
        process.exit(1);
      }
    } else if (arg === "--rules") {
      options.rulesDir = resolve(args[++i]);
    } else if (!arg.startsWith("-")) {
      files.push(arg);
    }

    i++;
  }

  return { files, options };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printUsage();
    process.exit(1);
  }

  const { files, options } = parseArgs(args);

  if (files.length === 0) {
    console.error("Error: No input files specified");
    printUsage();
    process.exit(1);
  }

  // Initialize rule engine
  const ruleEngine = new RuleEngine();
  try {
    await ruleEngine.loadRules(options.rulesDir);
  } catch (error) {
    console.error(`Error loading rules from ${options.rulesDir}:`, error);
    process.exit(1);
  }

  let allFindings: Awaited<ReturnType<typeof ruleEngine.analyze>> = [];

  for (const filePath of files) {
    try {
      const absolutePath = resolve(filePath);
      const content = await Bun.file(absolutePath).text();
      const parsed = parseSkillFile(absolutePath, content);
      const findings = ruleEngine.analyze(parsed);
      allFindings = allFindings.concat(findings);
    } catch (error) {
      console.error(`Error processing ${filePath}:`, error);
    }
  }

  // Output results
  if (options.format === "sarif") {
    console.log(formatSarifReport(allFindings, ruleEngine.getRules()));
  } else {
    printConsoleReport(allFindings);
  }

  // Exit with error code if critical or high severity issues found
  const hasCriticalOrHigh = allFindings.some(
    (f) => f.severity === "critical" || f.severity === "high"
  );
  if (hasCriticalOrHigh) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exit(1);
});
