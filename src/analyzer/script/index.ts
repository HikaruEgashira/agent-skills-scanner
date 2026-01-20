/**
 * Script Analyzer - Main Entry Point
 * Coordinates JavaScript and Shell script analysis
 */

import { JavaScriptAnalyzer, type ScriptFinding as JSFinding } from "./javascript-analyzer";
import { ShellAnalyzer, type ShellFinding } from "./shell-analyzer";

export type ScriptFinding = JSFinding | ShellFinding;

export interface ScriptAnalysisResult {
  filePath: string;
  fileType: "javascript" | "typescript" | "shell" | "unknown";
  findings: ScriptFinding[];
  statistics: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
}

export class ScriptAnalyzer {
  private jsAnalyzer: JavaScriptAnalyzer;
  private shellAnalyzer: ShellAnalyzer;

  constructor() {
    this.jsAnalyzer = new JavaScriptAnalyzer();
    this.shellAnalyzer = new ShellAnalyzer();
  }

  /**
   * Analyze a single script file
   */
  analyzeFile(filePath: string, content: string): ScriptAnalysisResult | null {
    const fileType = this.detectFileType(filePath, content);

    let findings: ScriptFinding[] = [];

    switch (fileType) {
      case "javascript":
      case "typescript":
        findings = this.jsAnalyzer.analyze(content, filePath);
        break;
      case "shell":
        findings = this.shellAnalyzer.analyze(content, filePath);
        break;
      default:
        return null;
    }

    if (findings.length === 0) {
      return null;
    }

    const statistics = this.calculateStatistics(findings);

    return {
      filePath,
      fileType,
      findings,
      statistics,
    };
  }

  /**
   * Analyze multiple script files
   */
  analyzeFiles(files: Array<{ path: string; content: string }>): ScriptAnalysisResult[] {
    const results: ScriptAnalysisResult[] = [];

    for (const file of files) {
      const result = this.analyzeFile(file.path, file.content);
      if (result) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Detect file type based on extension and content
   */
  private detectFileType(filePath: string, content: string): "javascript" | "typescript" | "shell" | "unknown" {
    // Check extension first
    if (/\.tsx?$/i.test(filePath)) return "typescript";
    if (/\.jsx?$/i.test(filePath)) return "javascript";
    if (/\.m?js$/i.test(filePath)) return "javascript";
    if (/\.(sh|bash|zsh)$/i.test(filePath)) return "shell";

    // Check shebang for shell scripts
    if (content.startsWith("#!/bin/sh") ||
        content.startsWith("#!/bin/bash") ||
        content.startsWith("#!/bin/zsh") ||
        content.startsWith("#!/usr/bin/env bash") ||
        content.startsWith("#!/usr/bin/env sh")) {
      return "shell";
    }

    // Check for node shebang
    if (content.startsWith("#!/usr/bin/env node") ||
        content.startsWith("#!/usr/bin/env bun")) {
      return "javascript";
    }

    // Heuristic: check content
    if (content.includes("import ") || content.includes("require(") || content.includes("export ")) {
      if (content.includes(": string") || content.includes(": number") || content.includes("interface ")) {
        return "typescript";
      }
      return "javascript";
    }

    if (content.includes("#!/bin") || /\b(echo|ls|cd|mkdir|rm)\b/.test(content)) {
      return "shell";
    }

    return "unknown";
  }

  /**
   * Calculate statistics for findings
   */
  private calculateStatistics(findings: ScriptFinding[]): {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  } {
    const stats = {
      total: findings.length,
      bySeverity: {} as Record<string, number>,
      byCategory: {} as Record<string, number>,
    };

    for (const finding of findings) {
      stats.bySeverity[finding.severity] = (stats.bySeverity[finding.severity] || 0) + 1;
      stats.byCategory[finding.category] = (stats.byCategory[finding.category] || 0) + 1;
    }

    return stats;
  }

  /**
   * Get overall statistics for multiple results
   */
  getOverallStatistics(results: ScriptAnalysisResult[]): {
    totalFiles: number;
    totalFindings: number;
    filesByType: Record<string, number>;
    findingsBySeverity: Record<string, number>;
    findingsByCategory: Record<string, number>;
  } {
    const stats = {
      totalFiles: results.length,
      totalFindings: 0,
      filesByType: {} as Record<string, number>,
      findingsBySeverity: {} as Record<string, number>,
      findingsByCategory: {} as Record<string, number>,
    };

    for (const result of results) {
      stats.totalFindings += result.findings.length;
      stats.filesByType[result.fileType] = (stats.filesByType[result.fileType] || 0) + 1;

      for (const [severity, count] of Object.entries(result.statistics.bySeverity)) {
        stats.findingsBySeverity[severity] = (stats.findingsBySeverity[severity] || 0) + count;
      }

      for (const [category, count] of Object.entries(result.statistics.byCategory)) {
        stats.findingsByCategory[category] = (stats.findingsByCategory[category] || 0) + count;
      }
    }

    return stats;
  }
}

// Re-export analyzer classes for direct use
export { JavaScriptAnalyzer } from "./javascript-analyzer";
export { ShellAnalyzer } from "./shell-analyzer";
export type { ScriptFinding as JavaScriptFinding } from "./javascript-analyzer";
export type { ShellFinding } from "./shell-analyzer";
