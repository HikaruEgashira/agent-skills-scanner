import type { Finding } from "../analyzer/rule-engine";

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  gray: "\x1b[90m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

function getSeverityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return COLORS.red + COLORS.bold;
    case "high":
      return COLORS.red;
    case "medium":
      return COLORS.yellow;
    case "low":
      return COLORS.blue;
    default:
      return COLORS.gray;
  }
}

function getSeverityIcon(severity: string): string {
  switch (severity) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}

export function formatConsoleReport(findings: Finding[]): string {
  if (findings.length === 0) {
    return `${COLORS.cyan}✓ No security issues found${COLORS.reset}\n`;
  }

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `${COLORS.bold}${COLORS.red}Found ${findings.length} security issue(s)${COLORS.reset}`
  );
  lines.push("");

  // Group by severity
  const bySeverity = findings.reduce(
    (acc, f) => {
      acc[f.severity] = acc[f.severity] || [];
      acc[f.severity].push(f);
      return acc;
    },
    {} as Record<string, Finding[]>
  );

  const severityOrder = ["critical", "high", "medium", "low"];

  for (const severity of severityOrder) {
    const severityFindings = bySeverity[severity];
    if (!severityFindings || severityFindings.length === 0) continue;

    lines.push(
      `${getSeverityColor(severity)}${getSeverityIcon(severity)} ${severity.toUpperCase()} (${severityFindings.length})${COLORS.reset}`
    );
    lines.push("");

    for (const finding of severityFindings) {
      lines.push(
        `  ${COLORS.gray}${finding.filePath}:${finding.line}:${finding.column}${COLORS.reset}`
      );
      lines.push(`  ${finding.message}`);
      lines.push(
        `  ${COLORS.gray}Rule: ${finding.ruleId}/${finding.patternId}${COLORS.reset}`
      );
      lines.push(`  ${COLORS.magenta}Match: "${finding.match}"${COLORS.reset}`);
      lines.push("");
    }
  }

  // Summary
  lines.push(`${COLORS.bold}Summary:${COLORS.reset}`);
  for (const severity of severityOrder) {
    const count = bySeverity[severity]?.length || 0;
    if (count > 0) {
      lines.push(
        `  ${getSeverityIcon(severity)} ${severity}: ${count}`
      );
    }
  }
  lines.push("");

  return lines.join("\n");
}

export function printConsoleReport(findings: Finding[]): void {
  console.log(formatConsoleReport(findings));
}
