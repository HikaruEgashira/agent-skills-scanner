# ADR-0002: セキュリティリスク分析

## Status

Accepted

## Date

2026-01-18

## Context

Agent Skills（SKILL.md）は、AIエージェントの振る舞いを定義するプロンプトファイルである。これらのファイルには、通常のコードとは異なる独自のセキュリティリスクが存在する。

## Decision

以下の脅威カテゴリを定義し、検出優先度マトリクスに基づいてスキャナーを設計する。

### 脅威カテゴリ

#### 1. プロンプトインジェクション（Priority: Critical）

AIエージェントの意図した動作を改ざんし、不正な操作を実行させる攻撃。

**直接型（Direct Injection）:**
- システムプロンプトの上書き試行
- ロール/ペルソナの変更指示
- 安全機能の無効化指示

```markdown
# 検出パターン例
- "ignore previous instructions"
- "you are now"
- "forget your rules"
- "system prompt:"
```

**間接型（Indirect Injection）:**
- 外部リソース読み込み時の悪意あるコンテンツ
- ツール出力を通じた攻撃
- チェーン攻撃（複数ステップでの誘導）

#### 2. ツール中毒（Tool Poisoning）（Priority: High）

ツールの説明やメタデータに悪意あるプロンプトを埋め込む攻撃。

**検出対象:**
- ツール説明文内の隠れた指示
- 過度に広い権限要求
- 不審なツール呼び出しパターン

```markdown
# 検出パターン例
- description内の"<system>"タグ
- 権限昇格を示唆する記述
- 他ツールへの不正な委任指示
```

#### 3. データ漏洩（Data Exfiltration）（Priority: High）

機密情報への無許可アクセスや外部送信を試みる攻撃。

**検出対象:**
- 環境変数の読み取り指示
- 認証情報へのアクセス
- 外部URLへのデータ送信
- ファイルシステムの探索

```markdown
# 検出パターン例
- "process.env"
- "~/.ssh/"
- "curl", "wget" + 外部URL
- API キー/トークンのパターン
```

#### 4. 難読化技術（Obfuscation）（Priority: Medium）

悪意あるコンテンツを検出困難にする技術。

**検出対象:**
- Unicode制御文字（RTL override, Zero-width characters）
- Base64エンコードされたペイロード
- 文字列分割・結合による回避
- コメント内の隠れた指示

```markdown
# 検出パターン例
- \u200B (Zero-width space)
- \u202E (RTL override)
- Base64パターン: [A-Za-z0-9+/]{20,}={0,2}
- HTMLコメント内の指示
```

#### 5. Rug Pull / サプライチェーン攻撃（Priority: Medium）

スキルの更新を通じて悪意あるコードを導入する攻撃。

**検出対象:**
- 外部リソースへの動的依存
- 実行時にコンテンツを取得する指示
- バージョン固定されていない依存関係

### 検出優先度マトリクス

| カテゴリ | 影響度 | 発生可能性 | 優先度 | Phase |
|---------|--------|------------|--------|-------|
| プロンプトインジェクション（直接） | Critical | High | P0 | 1 |
| プロンプトインジェクション（間接） | Critical | Medium | P0 | 1 |
| ツール中毒 | High | Medium | P1 | 1 |
| データ漏洩 | High | Medium | P1 | 1 |
| 難読化 | Medium | High | P1 | 1 |
| Rug Pull | High | Low | P2 | 2 |

### 検出手法

**Phase 1: パターンマッチング**
- 正規表現ベースのルールエンジン
- YAMLで定義可能なカスタムルール
- 高速なファイルスキャン
- 偽陽性を許容しつつ高い検出率を目指す

**Phase 2: LLMベース解析（将来）**
- セマンティック解析による意図検出
- コンテキストを考慮した判定
- 偽陽性の削減

## Consequences

### Positive

- 体系的な脅威分類により、漏れのない検出が可能
- 優先度に基づく段階的な実装が可能
- 新たな脅威の追加が容易

### Negative

- パターンマッチングには限界があり、高度な攻撃は検出困難
- ルールの継続的な更新が必要

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MCP Security Vulnerabilities](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [LLM Security Risks 2026](https://sombrainc.com/blog/llm-security-risks-2026)
