export interface PatternMatch {
  ruleId: string;
  patternId: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  match: string;
  line: number;
  column: number;
  endColumn: number;
}

export interface Pattern {
  id: string;
  pattern: string;
  flags: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
}

export function matchPattern(
  content: string,
  ruleId: string,
  pattern: Pattern
): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const lines = content.split("\n");

  // Handle Unicode escape patterns
  let regexPattern = pattern.pattern;

  // Convert \uXXXX to actual Unicode characters for matching
  regexPattern = regexPattern.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  try {
    const flags = pattern.flags || "g";
    const regex = new RegExp(regexPattern, flags.includes("g") ? flags : flags + "g");

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      let match: RegExpExecArray | null;

      // Reset regex lastIndex for each line
      regex.lastIndex = 0;

      while ((match = regex.exec(line)) !== null) {
        matches.push({
          ruleId,
          patternId: pattern.id,
          message: pattern.message,
          severity: pattern.severity,
          match: match[0],
          line: lineIndex + 1,
          column: match.index + 1,
          endColumn: match.index + match[0].length + 1,
        });

        // Prevent infinite loop for zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }
  } catch (error) {
    console.error(`Invalid regex pattern: ${pattern.pattern}`, error);
  }

  return matches;
}
