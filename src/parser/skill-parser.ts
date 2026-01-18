export interface SkillSection {
  name: string;
  content: string;
  startLine: number;
  endLine: number;
}

export interface ParsedSkill {
  filePath: string;
  rawContent: string;
  sections: SkillSection[];
  metadata: Record<string, string>;
}

export function parseSkillFile(filePath: string, content: string): ParsedSkill {
  const lines = content.split("\n");
  const sections: SkillSection[] = [];
  const metadata: Record<string, string> = {};

  let currentSection: SkillSection | null = null;
  let sectionContent: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    // Check for markdown headers (## or #)
    const headerMatch = line.match(/^(#{1,6})\s+(.+)$/);

    if (headerMatch) {
      // Save previous section if exists
      if (currentSection) {
        currentSection.content = sectionContent.join("\n");
        currentSection.endLine = lineNumber - 1;
        sections.push(currentSection);
      }

      // Start new section
      currentSection = {
        name: headerMatch[2].trim(),
        content: "",
        startLine: lineNumber,
        endLine: lineNumber,
      };
      sectionContent = [];
    } else if (currentSection) {
      sectionContent.push(line);
    } else {
      // Content before first header - check for frontmatter or metadata
      const metadataMatch = line.match(/^(\w+):\s*(.+)$/);
      if (metadataMatch) {
        metadata[metadataMatch[1].toLowerCase()] = metadataMatch[2];
      }
    }
  }

  // Save last section
  if (currentSection) {
    currentSection.content = sectionContent.join("\n");
    currentSection.endLine = lines.length;
    sections.push(currentSection);
  }

  return {
    filePath,
    rawContent: content,
    sections,
    metadata,
  };
}

export function getLineNumber(content: string, charIndex: number): number {
  const substring = content.substring(0, charIndex);
  return substring.split("\n").length;
}

export function getLineContent(content: string, lineNumber: number): string {
  const lines = content.split("\n");
  return lines[lineNumber - 1] || "";
}
