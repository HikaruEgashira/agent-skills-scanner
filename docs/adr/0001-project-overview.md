# ADR-0001: Agent Skills Scanner プロジェクト概要

## Status

Accepted

## Date

2026-01-18

## Context

### 背景

Agent Skills マーケットプレイス（特にSkillsMP.com）には60,000以上のAgent Skillsが登録されており、Claude Code、Codex CLI、ChatGPT向けのSKILL.mdフォーマットで提供されている。

これらのスキルはGitHubの公開リポジトリから自動収集されており（最低2スター要件）、独立したコミュニティプロジェクトとして運営されている（Anthropic非公式）。

### 問題

1. **セキュリティ検証の欠如**: SkillsMP自体が「マルウェアが含まれる可能性がある」と警告している
2. **急速な成長**: 60,000+のスキルを手動で検証することは不可能
3. **新しい攻撃ベクトル**: SKILL.mdフォーマットはプロンプトインジェクションの新たな攻撃面を形成

### 既存ソリューションの限界

- `mcp-scan`: MCP Server向けであり、SKILL.mdフォーマットには非対応
- 汎用的なセキュリティスキャナー: AIエージェント特有の脅威（プロンプトインジェクション等）を検出できない

## Decision

SKILL.mdフォーマット専用のセキュリティスキャナーを新規開発する。

### スコープ

**Phase 1（MVP）:**
- SKILL.mdファイルの静的解析
- パターンベースのプロンプトインジェクション検出
- 難読化技術の検出（Unicode制御文字、Base64エンコード等）
- SARIF形式でのレポート出力

**Phase 2（将来）:**
- LLMベースの意味解析
- 継続的スキャン（CI/CD統合）
- SkillsMP APIとの連携

### 対象外

- 実行時の動的解析
- MCPサーバーのスキャン（既存ツールで対応可能）
- スキルの自動修正

## Consequences

### Positive

- Agent Skillsエコシステムのセキュリティ向上に貢献
- 開発者がスキルを公開前に検証可能
- セキュリティ研究のためのデータセット構築

### Negative

- 新規プロジェクトのため、メンテナンスコストが発生
- 検出ルールの継続的な更新が必要
- 偽陽性/偽陰性のチューニングが必要

### Risks

- 攻撃者が検出を回避する新手法を開発する可能性
- SkillsMPのフォーマット変更への追従が必要

## References

- [SkillsMP](https://skillsmp.com/)
- [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)
- [MCP Security Vulnerabilities](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
