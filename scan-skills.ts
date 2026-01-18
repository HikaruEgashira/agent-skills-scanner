#!/usr/bin/env bun
/**
 * Skill Scanner - Scans skills from skillsmp.com for security issues
 */

import * as yaml from "js-yaml";
import { resolve, dirname, join } from "node:path";

// Security patterns from rules
const securityPatterns = [
  // Prompt Injection
  { id: "ignore-previous", pattern: /ignore\s+(all\s+)?previous\s+instructions?/i, severity: "critical", message: "Prompt injection: attempt to ignore previous instructions" },
  { id: "you-are-now", pattern: /you\s+are\s+now/i, severity: "critical", message: "Prompt injection: role manipulation attempt" },
  { id: "system-tag", pattern: /<system>/i, severity: "critical", message: "Prompt injection: fake system tag detected" },
  { id: "new-instructions", pattern: /new\s+instructions?\s*:/i, severity: "high", message: "Prompt injection: attempt to inject new instructions" },
  { id: "forget-previous", pattern: /forget\s+(everything|all|what)/i, severity: "critical", message: "Prompt injection: attempt to make agent forget context" },
  { id: "override-rules", pattern: /(override|bypass|ignore)\s+(safety|security|rules?)/i, severity: "critical", message: "Prompt injection: attempt to override safety rules" },
  { id: "act-as", pattern: /act\s+as\s+(if\s+)?(you\s+are|an?\s+)/i, severity: "high", message: "Prompt injection: role impersonation attempt" },
  { id: "developer-mode", pattern: /(developer|admin|root|sudo)\s+mode/i, severity: "critical", message: "Prompt injection: privilege escalation attempt" },
  { id: "disregard-instructions", pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)/i, severity: "critical", message: "Prompt injection: disregard instructions attempt" },
  { id: "jailbreak-dan", pattern: /(DAN|do\s+anything\s+now|jailbreak)/i, severity: "critical", message: "Prompt injection: jailbreak attempt (DAN pattern)" },
  { id: "pretend-to-be", pattern: /pretend\s+(to\s+be|you\s+are)/i, severity: "high", message: "Prompt injection: role manipulation via pretend" },
  { id: "hidden-instruction-marker", pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>/, severity: "critical", message: "Prompt injection: Llama/system instruction markers detected" },
  { id: "assistant-response-fake", pattern: /^(Assistant|Claude|AI):\s+/im, severity: "high", message: "Prompt injection: fake assistant response prefix" },
  { id: "important-override", pattern: /IMPORTANT:\s*(ignore|override|disregard|forget)/i, severity: "critical", message: "Prompt injection: IMPORTANT override attempt" },

  // Tool Poisoning
  { id: "description-system-tag", pattern: /description:\s*["']?.*<system>/i, severity: "critical", message: "Tool poisoning: system tag in tool description" },
  { id: "hidden-instructions", pattern: /description:\s*["']?.*\b(must|always|never|ignore)\b.*instructions?/i, severity: "high", message: "Tool poisoning: hidden instructions in description" },
  { id: "privilege-escalation", pattern: /(sudo|root|admin|elevated)\s+(access|privileges?|permissions?)/i, severity: "critical", message: "Tool poisoning: privilege escalation attempt" },
  { id: "shell-injection-subshell", pattern: /\$\([^)]+\)/, severity: "critical", message: "Tool poisoning: shell subshell command injection" },
  { id: "shell-injection-backtick-dangerous", pattern: /`(?:rm|curl|wget|nc|bash|sh|eval|exec)[^`]*`/i, severity: "critical", message: "Tool poisoning: dangerous command in backticks" },
  { id: "shell-injection-rm", pattern: /(;|&&|\|)\s*rm\s/, severity: "critical", message: "Tool poisoning: destructive shell command chain" },
  { id: "shell-injection-pipe", pattern: /\|\s*(sh|bash|zsh|eval)/, severity: "critical", message: "Tool poisoning: shell pipe execution" },
  { id: "execute-arbitrary", pattern: /(exec|eval|spawn)\s*\(/i, severity: "high", message: "Tool poisoning: arbitrary code execution pattern" },
  { id: "hidden-callback", pattern: /(fetch|axios|http\.request|XMLHttpRequest)\s*\(\s*['"]https?:\/\//, severity: "high", message: "Tool poisoning: external callback attempt" },
  { id: "fs-operations", pattern: /(fs\.write|fs\.unlink|fs\.rm|rimraf)/, severity: "high", message: "Tool poisoning: dangerous filesystem operation" },
  { id: "curl-post-data", pattern: /curl\s+.*(-d|--data|--data-raw)\s+.*\$/, severity: "high", message: "Tool poisoning: curl POST with variable data (potential exfiltration)" },
  { id: "reverse-shell", pattern: /(nc|netcat|ncat)\s+.*-e\s*(sh|bash|\/bin)/i, severity: "critical", message: "Tool poisoning: reverse shell pattern detected" },
  { id: "base64-decode-execute", pattern: /(base64\s+(-d|--decode)|atob).*\|\s*(sh|bash|eval)/i, severity: "critical", message: "Tool poisoning: base64 decode and execute pattern" },
  { id: "environment-variable-exfil", pattern: /(curl|wget|fetch).*\$[A-Z_]+.*/, severity: "high", message: "Tool poisoning: environment variable in network request" },
];

interface Finding {
  patternId: string;
  severity: string;
  message: string;
  line: number;
  match: string;
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
          message: patternDef.message,
          line: i + 1,
          match: match[0],
        });
      }
    }
  }

  return findings;
}

// Skills to scan - expanded list (pages 1-2 + recent)
const skillUrls = [
  // Page 1 - Popular
  "https://skillsmp.com/skills/n8n-io-n8n-claude-skills-create-pr-skill-md",
  "https://skillsmp.com/skills/f-awesome-chatgpt-prompts-plugins-claude-prompts-chat-skills-skill-lookup-skill-md",
  "https://skillsmp.com/skills/f-awesome-chatgpt-prompts-plugins-claude-prompts-chat-skills-prompt-lookup-skill-md",
  "https://skillsmp.com/skills/langgenius-dify-claude-skills-frontend-code-review-skill-md",
  "https://skillsmp.com/skills/langgenius-dify-claude-skills-component-refactoring-skill-md",
  "https://skillsmp.com/skills/langgenius-dify-claude-skills-orpc-contract-first-skill-md",
  "https://skillsmp.com/skills/langgenius-dify-claude-skills-skill-creator-skill-md",
  "https://skillsmp.com/skills/langgenius-dify-claude-skills-frontend-testing-skill-md",
  "https://skillsmp.com/skills/electron-electron-claude-skills-electron-chromium-upgrade-skill-md",
  "https://skillsmp.com/skills/pytorch-pytorch-claude-skills-at-dispatch-v2-skill-md",
  "https://skillsmp.com/skills/pytorch-pytorch-claude-skills-docstring-skill-md",
  "https://skillsmp.com/skills/pytorch-pytorch-claude-skills-skill-writer-skill-md",
  // Page 2 - Bun skills
  "https://skillsmp.com/skills/oven-sh-bun-claude-skills-writing-dev-server-tests-skill-md",
  "https://skillsmp.com/skills/oven-sh-bun-claude-skills-writing-bundler-tests-skill-md",
  "https://skillsmp.com/skills/oven-sh-bun-claude-skills-implementing-jsc-classes-cpp-skill-md",
  "https://skillsmp.com/skills/oven-sh-bun-claude-skills-zig-system-calls-skill-md",
  "https://skillsmp.com/skills/oven-sh-bun-claude-skills-implementing-jsc-classes-zig-skill-md",
  // Page 2 - 33-js-concepts skills
  "https://skillsmp.com/skills/leonardomso-33-js-concepts-opencode-skill-concept-workflow-skill-md",
  "https://skillsmp.com/skills/leonardomso-33-js-concepts-opencode-skill-fact-check-skill-md",
  "https://skillsmp.com/skills/leonardomso-33-js-concepts-opencode-skill-write-concept-skill-md",
  "https://skillsmp.com/skills/leonardomso-33-js-concepts-opencode-skill-seo-review-skill-md",
  // Recent skills - sorted by newest
  "https://skillsmp.com/skills/rysweet-azure-tenant-grapher-claude-skills-mcp-manager-skill-md",
  "https://skillsmp.com/skills/thinkex-oss-thinkex-agent-skills-git-guidelines-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-github-issue-creation-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-typescript-development-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-devops-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-solidity-development-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-go-development-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-makefile-update-skill-md",
  "https://skillsmp.com/skills/hiromaily-go-crypto-wallet-claude-skills-shell-scripts-skill-md",
  // Security category skills
  "https://skillsmp.com/skills/wshobson-agents-plugins-hr-legal-compliance-skills-gdpr-data-handling-skill-md",
  "https://skillsmp.com/skills/wshobson-agents-plugins-kubernetes-operations-skills-k8s-security-policies-skill-md",
  "https://skillsmp.com/skills/wshobson-agents-plugins-cicd-automation-skills-secrets-management-skill-md",
  "https://skillsmp.com/skills/wshobson-agents-plugins-developer-essentials-skills-auth-implementation-patterns-skill-md",
  "https://skillsmp.com/skills/wshobson-agents-plugins-cloud-infrastructure-skills-mtls-configuration-skill-md",
  "https://skillsmp.com/skills/wshobson-agents-plugins-security-scanning-skills-sast-configuration-skill-md",
  "https://skillsmp.com/skills/github-awesome-copilot-skills-azure-role-selector-skill-md",
  "https://skillsmp.com/skills/davila7-claude-code-templates-cli-tool-components-skills-development-senior-secops-skill-md",
  "https://skillsmp.com/skills/davila7-claude-code-templates-cli-tool-components-skills-enterprise-communication-data-privacy-compliance-skill-md",
];

interface ScanResult {
  url: string;
  name: string;
  author: string;
  findings: Finding[];
  scannedAt: string;
}

async function fetchSkillContent(url: string): Promise<{ content: string; name: string; author: string } | null> {
  try {
    const response = await fetch(url);
    const html = await response.text();

    // Extract skill name from title
    const titleMatch = html.match(/<title>([^<]+)<\/title>/);
    const title = titleMatch ? titleMatch[1] : "Unknown";
    const nameParts = title.split(" - ");
    const name = nameParts[0] || "Unknown";

    // Extract author from JSON-LD
    const jsonLdMatch = html.match(/<script type="application\/ld\+json">([^<]+)<\/script>/);
    let author = "Unknown";
    if (jsonLdMatch) {
      try {
        const jsonLd = JSON.parse(jsonLdMatch[1]);
        author = jsonLd.author?.name || "Unknown";
      } catch {}
    }

    // Extract main content (simplified extraction)
    const mainMatch = html.match(/<main[^>]*>([\s\S]*?)<\/main>/);
    const content = mainMatch ? mainMatch[1] : html;

    return { content, name, author };
  } catch (error) {
    console.error(`Error fetching ${url}:`, error);
    return null;
  }
}

async function main() {
  console.log("=== Skill Security Scanner ===\n");

  const results: ScanResult[] = [];
  const scannedSkills: string[] = [];

  for (const url of skillUrls) {
    console.log(`Scanning: ${url}`);
    const skill = await fetchSkillContent(url);

    if (!skill) {
      console.log(`  ❌ Failed to fetch\n`);
      continue;
    }

    const findings = scanContent(skill.content);
    scannedSkills.push(`${skill.name} (${skill.author})`);

    if (findings.length > 0) {
      console.log(`  ⚠️ Found ${findings.length} potential issues:`);
      for (const finding of findings) {
        console.log(`    [${finding.severity.toUpperCase()}] ${finding.message} (line ${finding.line})`);
      }

      results.push({
        url,
        name: skill.name,
        author: skill.author,
        findings,
        scannedAt: new Date().toISOString(),
      });
    } else {
      console.log(`  ✅ No security issues found`);
    }
    console.log("");
  }

  // Save scanned skills to progress.txt
  const progressContent = `# Scanned Skills Progress
Last updated: ${new Date().toISOString()}

## Scanned Skills (${scannedSkills.length})
${scannedSkills.map((s, i) => `${i + 1}. ${s}`).join("\n")}

## Findings Summary
- Total skills scanned: ${scannedSkills.length}
- Skills with issues: ${results.length}
`;

  await Bun.write("progress.txt", progressContent);
  console.log("Progress saved to progress.txt");

  // Generate reports for skills with findings
  if (results.length > 0) {
    const reportsDir = resolve(import.meta.dir, "reports");
    await Bun.write(`${reportsDir}/.gitkeep`, "");

    for (const result of results) {
      const safeName = result.name.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase();
      const reportPath = `${reportsDir}/${safeName}.md`;

      const reportContent = `# Security Report: ${result.name}

**Author:** ${result.author}
**URL:** ${result.url}
**Scanned:** ${result.scannedAt}

## Findings

${result.findings.map((f) => `### ${f.severity.toUpperCase()}: ${f.patternId}

- **Message:** ${f.message}
- **Line:** ${f.line}
- **Match:** \`${f.match}\`
`).join("\n")}
`;

      await Bun.write(reportPath, reportContent);
      console.log(`Report saved to ${reportPath}`);
    }
  }

  console.log("\n=== Scan Complete ===");
}

main().catch(console.error);
