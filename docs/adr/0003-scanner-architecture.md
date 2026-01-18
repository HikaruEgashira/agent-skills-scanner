# ADR-0003: スキャナーアーキテクチャ設計

## Status

Accepted

## Date

2026-01-18

## Context

ADR-0001で定義したスコープとADR-0002で定義した脅威カテゴリに基づき、SKILL.mdファイルのセキュリティスキャナーのアーキテクチャを設計する必要がある。

### 要件

**機能要件:**
- SKILL.mdファイルの解析
- パターンベースの脅威検出
- カスタムルールの定義・追加
- 標準フォーマット（SARIF）での出力

**非機能要件:**
- 高速なスキャン（大量ファイルへの対応）
- 拡張性（新しい検出ルールの追加容易性）
- CI/CD統合の容易性

## Decision

### 技術スタック

| 項目 | 選定技術 | 理由 |
|------|----------|------|
| 言語 | TypeScript | 型安全性、エコシステムの充実 |
| ランタイム | Bun | 高速な起動時間、TypeScriptネイティブ対応 |
| ルール定義 | YAML | 人間が読みやすく、GitHubでの差分確認が容易 |
| 出力形式 | SARIF | GitHub Advanced Security統合、業界標準 |

### アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Interface                             │
│                  (bun run scan <path>)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    Input Stage                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ File Finder │  │ Git Fetcher │  │ SkillsMP Connector │  │
│  │ (local)     │  │ (remote)    │  │ (API - Phase 2)    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼───────────────────┬┼─────────────┘
          │                │                   ││
          └────────────────┴───────────────────┘│
                           │                    │
┌──────────────────────────▼────────────────────▼─────────────┐
│                    Parser Stage                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              SKILL.md Parser                            │ │
│  │  - Frontmatter extraction (YAML)                       │ │
│  │  - Markdown section parsing                            │ │
│  │  - Metadata normalization                              │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Analyzer Stage                             │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────────┐  │
│  │ Rule Engine    │  │ Pattern Matcher │  │ LLM Analyzer │  │
│  │ (YAML rules)   │  │ (regex)         │  │ (Phase 2)    │  │
│  └───────┬────────┘  └───────┬─────────┘  └──────┬───────┘  │
│          │                   │                   │          │
│          └───────────────────┴───────────────────┘          │
│                              │                              │
│                    ┌─────────▼─────────┐                    │
│                    │ Finding Collector │                    │
│                    │ - Deduplication   │                    │
│                    │ - Severity calc   │                    │
│                    └───────────────────┘                    │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Reporter Stage                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ SARIF Output │  │ JSON Output  │  │ Console Output   │   │
│  │ (for CI/CD)  │  │ (for API)    │  │ (for CLI)        │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### ディレクトリ構造

```
agent-skills-scanner/
├── src/
│   ├── cli/              # CLIエントリーポイント
│   │   └── index.ts
│   ├── input/            # 入力ステージ
│   │   ├── file-finder.ts
│   │   ├── git-fetcher.ts
│   │   └── index.ts
│   ├── parser/           # パーサーステージ
│   │   ├── skill-parser.ts
│   │   ├── frontmatter.ts
│   │   └── index.ts
│   ├── analyzer/         # 分析ステージ
│   │   ├── rule-engine.ts
│   │   ├── pattern-matcher.ts
│   │   ├── finding.ts
│   │   └── index.ts
│   ├── reporter/         # レポーターステージ
│   │   ├── sarif.ts
│   │   ├── json.ts
│   │   ├── console.ts
│   │   └── index.ts
│   └── types/            # 型定義
│       └── index.ts
├── rules/                # 検出ルール（YAML）
│   ├── prompt-injection.yaml
│   ├── tool-poisoning.yaml
│   ├── data-exfiltration.yaml
│   └── obfuscation.yaml
├── tests/                # テスト
│   ├── fixtures/         # テスト用SKILL.mdファイル
│   └── *.test.ts
├── docs/
│   └── adr/              # ADR
└── package.json
```

### ルール定義フォーマット

```yaml
# rules/prompt-injection.yaml
rules:
  - id: PI001
    name: direct-instruction-override
    description: 直接的な指示上書きの試行を検出
    severity: critical
    category: prompt-injection
    patterns:
      - regex: "ignore\\s+(all\\s+)?previous\\s+instructions?"
        flags: i
      - regex: "forget\\s+(your|all)\\s+rules?"
        flags: i
      - regex: "you\\s+are\\s+now\\s+[a-z]+"
        flags: i
    message: "プロンプトインジェクションの可能性: 指示の上書きを試行しています"

  - id: PI002
    name: system-prompt-injection
    description: システムプロンプトの注入を検出
    severity: critical
    category: prompt-injection
    patterns:
      - regex: "<system>"
      - regex: "\\[SYSTEM\\]"
      - regex: "system\\s*prompt\\s*:"
        flags: i
    message: "プロンプトインジェクションの可能性: システムプロンプトの注入を試行しています"
```

### SARIF出力例

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "agent-skills-scanner",
          "version": "1.0.0",
          "rules": [
            {
              "id": "PI001",
              "name": "direct-instruction-override",
              "shortDescription": {
                "text": "直接的な指示上書きの試行を検出"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "PI001",
          "level": "error",
          "message": {
            "text": "プロンプトインジェクションの可能性: 指示の上書きを試行しています"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "skills/malicious/SKILL.md"
                },
                "region": {
                  "startLine": 15,
                  "startColumn": 1
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Consequences

### Positive

- パイプラインアーキテクチャにより、各ステージが独立してテスト可能
- YAMLルールにより、コード変更なしで検出パターンを追加可能
- SARIF出力により、GitHub Advanced Securityとの統合が容易
- Bunの採用により、高速な起動と実行が期待できる

### Negative

- Bunはまだ成熟途上であり、互換性問題が発生する可能性
- YAMLルールは複雑なロジックの表現に限界がある

### Technical Debt

- Phase 2のLLM Analyzerは未実装としてスタブを用意
- SkillsMP APIコネクタはAPIの公開を待って実装

## References

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Bun Documentation](https://bun.sh/docs)
- [Semgrep Architecture](https://semgrep.dev/docs/) （参考：類似ツールのアーキテクチャ）
