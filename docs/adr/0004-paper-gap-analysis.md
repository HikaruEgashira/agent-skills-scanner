# ADR-0004: 論文「Agent Skills in the Wild」とのギャップ分析

## Status

Proposed

## Date

2026-01-20

## Context

論文「Agent Skills in the Wild」(arXiv:2601.10338) は、42,447のエージェントスキルを収集し、31,132の一意のスキルを分析した大規模研究である。彼らが開発したSkillScanツールは、静的解析とLLMベースの分類を組み合わせた多段階パイプラインを使用し、26.1%のスキルに脆弱性を検出した（精度86.7%、再現率82.5%）。

本ドキュメントでは、論文の知見と現在のagent-skills-scannerプロダクトの実装状況を比較し、重要なギャップを特定する。

## 論文の主要な知見

### 1. 脅威の規模

- **分析規模**: 31,132の一意のスキル（2025年12月スナップショット）
- **脆弱性検出率**: 26.1%のスキルに脆弱性パターンを検出
- **実行可能スクリプト付きスキル**: 2.12倍の脆弱性リスク（オッズ比2.12、p < 0.001）
- **動的検証**: 高信頼度25スキル中72%が実際に悪用可能な挙動を示した

### 2. 脆弱性の分類

論文は14の脆弱性パターンを4つの主要カテゴリに分類：

1. **Prompt Injection（プロンプトインジェクション）**
   - 直接的な指示の上書き
   - システムプロンプトの操作
   - ロール操作

2. **Data Exfiltration（データ漏洩）**
   - 環境変数へのアクセス
   - 認証情報の窃取
   - 外部へのデータ送信

3. **Privilege Escalation（権限昇格）**
   - ツールの説明文への悪意ある指示の埋め込み
   - 過度な権限要求
   - シェルコマンドインジェクション

4. **Supply Chain Risk（サプライチェーンリスク）**
   - 外部リソースへの動的依存
   - バージョン固定されていない依存関係
   - 実行時のコード取得

### 3. SkillScanのアーキテクチャ

- **静的解析**: バンドルされたスクリプトの解析
- **LLMベース分類**: SKILL.mdコンテンツの意味論的分析
- **多段階パイプライン**: 再現性のある静的チェック + セマンティック判定
- **動的検証**: 高信頼度の検出結果に対する実行時検証

### 4. 推奨される対策

論文は以下の具体的な対策を推奨：

1. **スキル承認をセキュリティ境界として扱う**
2. **失敗の定義**: 予期しないファイルアクセス、ネットワーク通信、コマンド実行
3. **ログとモニタリング**: スキルのロード、リソース使用、ダウンロード、外部接続を記録
4. **静的パターンチェックの優先**: 再現性のため
5. **LLM分類は意味判定が必要な場合のみ使用**

## 現在のプロダクトの実装状況

### ✅ 実装済み

1. **静的パターンマッチング**
   - 正規表現ベースのルールエンジン (src/analyzer/rule-engine.ts)
   - YAMLでのカスタムルール定義 (rules/*.yaml)
   - 4つのルールファイル:
     - prompt-injection.yaml (14パターン)
     - tool-poisoning.yaml (14パターン)
     - data-exfiltration.yaml (10パターン)
     - obfuscation.yaml (10パターン)

2. **基本的な脅威カテゴリ**
   - プロンプトインジェクション: 論文と同様のパターン
   - ツール中毒（Tool Poisoning）: シェルインジェクション、権限昇格
   - データ漏洩: 環境変数、認証情報、外部通信
   - 難読化: Unicode制御文字、Base64エンコード

3. **アーキテクチャ**
   - パイプラインアーキテクチャ（Input → Parser → Analyzer → Reporter）
   - SARIF出力対応の設計（src/reporter/sarif.ts）
   - CLI インターフェース

### ❌ 未実装（重要なギャップ）

#### 1. 実行可能スクリプトの解析 ⚠️ **最重要**

**論文の知見**: スクリプト付きスキルは2.12倍のリスク

**現状**:
- SKILL.mdのテキストのみをスキャン
- バンドルされたスクリプトファイル（.js、.ts、.sh等）は未分析

**必要な実装**:
```typescript
// 必要な機能
interface SkillPackage {
  skillMd: string;
  scripts: {
    path: string;
    content: string;
    type: 'javascript' | 'typescript' | 'shell' | 'python';
  }[];
}

// スクリプト特有の検出パターン
- AST解析（JavaScript/TypeScript）
- シェルコマンド解析（bash/sh）
- 危険なAPI呼び出しの検出
  - fs.readFile()、fs.writeFile()
  - child_process.exec()、spawn()
  - fetch()、axios.get() への外部URL
```

#### 2. LLMベースのセマンティック分析

**論文の知見**: 精度86.7%、再現率82.5%の検出性能

**現状**:
- パターンマッチングのみ
- コンテキストを考慮した判定なし

**必要な実装**:
```typescript
interface LLMAnalyzer {
  analyzeIntent(content: string): {
    isVulnerable: boolean;
    category: VulnerabilityCategory;
    confidence: number;
    reasoning: string;
  };
}

// フォールバック戦略
- 静的パターンマッチングで高速フィルタリング
- 疑わしいケースのみLLM分析（コスト削減）
- 高信頼度の検出結果を優先
```

#### 3. 動的検証機能

**論文の知見**: 高信頼度25スキル中72%が実際に悪用可能

**現状**:
- 静的解析のみ
- 実行時の挙動検証なし

**必要な実装**:
```typescript
interface DynamicValidator {
  // サンドボックス環境でスキルを実行
  executeInSandbox(skill: Skill): {
    fileAccess: string[];      // アクセスされたファイル
    networkRequests: string[]; // 外部通信先
    commandsExecuted: string[];// 実行されたコマンド
    environmentAccess: string[];// 読み取られた環境変数
  };
}

// 実装アプローチ
- Docker/VM ベースのサンドボックス
- strace/dtruss でシステムコール監視
- ネットワーク通信のプロキシ記録
- ファイルシステムの差分記録
```

#### 4. サプライチェーンリスク分析

**論文のカテゴリ**: Supply Chain Risk

**現状**:
- 外部依存関係の検出なし
- 動的コード取得の検出なし

**必要な実装**:
```typescript
interface SupplyChainAnalyzer {
  // 依存関係の解析
  analyzeDependencies(skill: Skill): {
    externalUrls: string[];           // 外部URL
    dynamicImports: string[];         // 動的import
    unpinnedVersions: string[];       // バージョン固定なし
    suspiciousDownloads: string[];    // 実行時ダウンロード
  };
}

// 検出パターン
- import() / require() の動的使用
- fetch() / curl によるスクリプトのダウンロード
- eval() / Function() による実行時コード生成
- package.json の依存関係チェック
```

#### 5. 統計的検証とメトリクス

**論文のアプローチ**:
- 検証セットでの精度・再現率の測定
- オッズ比、p値による統計的有意性の検証
- 偽陽性・偽陰性の定量評価

**現状**:
- 検証データセットなし
- 精度・再現率の測定なし
- 統計的検証なし

**必要な実装**:
```typescript
interface ValidationMetrics {
  precision: number;    // 精度
  recall: number;       // 再現率
  f1Score: number;      // F1スコア
  falsePositiveRate: number;
  falseNegativeRate: number;

  // カテゴリ別メトリクス
  byCategory: Map<string, {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
  }>;
}

// 検証データセットの作成
- 既知の悪意あるスキル（ground truth）
- 既知の安全なスキル
- 手動でラベル付けされた検証セット
```

#### 6. ログとモニタリング機能

**論文の推奨**: スキルロード、リソース使用、外部接続を記録

**現状**:
- ログ機能なし
- モニタリング機能なし

**必要な実装**:
```typescript
interface SkillMonitor {
  // スキルのロードとリソース使用を記録
  logSkillLoad(skill: Skill, context: {
    timestamp: string;
    userId: string;
    sessionId: string;
  }): void;

  logResourceAccess(event: {
    type: 'file' | 'network' | 'env' | 'command';
    resource: string;
    action: 'read' | 'write' | 'execute';
    allowed: boolean;
    timestamp: string;
  }): void;

  // アラート生成
  generateAlert(severity: 'low' | 'medium' | 'high' | 'critical',
                message: string): void;
}

// 統合先
- Syslog / Journal
- SIEM (Security Information and Event Management)
- CloudWatch / Datadog
```

#### 7. 大規模スキャンの最適化

**論文の規模**: 31,132スキルの分析

**現状**:
- 小規模スキャン向け
- 並列処理なし
- 結果のキャッシュなし

**必要な実装**:
```typescript
interface ScalableScanner {
  // 並列処理
  scanBatch(skills: Skill[], options: {
    concurrency: number;
    timeout: number;
  }): Promise<ScanResult[]>;

  // 差分スキャン
  scanDelta(previousScan: ScanResult[],
            currentSkills: Skill[]): Promise<ScanResult[]>;

  // 結果のキャッシュ
  cacheResults(skill: Skill, result: ScanResult): void;
  getCachedResult(skillHash: string): ScanResult | null;
}
```

## ギャップの優先順位付け

| ギャップ | 影響度 | 実装難易度 | 優先度 | フェーズ |
|---------|--------|------------|--------|---------|
| 1. スクリプト解析 | Critical | Medium | **P0** | Phase 2 |
| 2. 統計的検証 | High | Low | **P0** | Phase 2 |
| 3. LLMセマンティック分析 | High | High | **P1** | Phase 3 |
| 4. サプライチェーン分析 | High | Medium | **P1** | Phase 2 |
| 5. ログ・モニタリング | Medium | Low | **P1** | Phase 2 |
| 6. 動的検証 | High | Very High | **P2** | Phase 4 |
| 7. 大規模スキャン最適化 | Medium | Medium | **P2** | Phase 3 |

### 優先順位の理由

**P0 (最優先):**
- **スクリプト解析**: 論文によれば2.12倍のリスク。現状では最大の検出漏れ
- **統計的検証**: 実装は容易で、ツールの信頼性を定量的に証明できる

**P1 (高優先):**
- **LLMセマンティック分析**: 論文の精度86.7%を達成するための鍵
- **サプライチェーン分析**: 新興の脅威ベクトル、実装は中程度
- **ログ・モニタリング**: 論文が明示的に推奨、実装は容易

**P2 (中優先):**
- **動的検証**: 高い価値だが、サンドボックス環境の構築が複雑
- **大規模スキャン最適化**: 現時点では小規模でも運用可能

## Phase 2 実装計画

### 2.1 スクリプト解析機能

**実装内容:**
```typescript
// src/analyzer/script-analyzer.ts
- JavaScript/TypeScript: AST解析（Babel/SWC）
- Shell: bashlex でパース
- Python: AST解析（python-ast）

// 新しいルールファイル
- rules/script-injection.yaml
- rules/dangerous-apis.yaml
```

**検出パターン例:**
- `child_process.exec(userInput)` - コマンドインジェクション
- `eval(downloadedCode)` - 動的コード実行
- `fetch(env.PRIVATE_URL)` - データ漏洩
- `fs.readFile('~/.ssh/id_rsa')` - 認証情報窃取

### 2.2 統計的検証フレームワーク

**実装内容:**
```typescript
// tests/validation/
- validation-dataset.yaml  // 既知の悪意・安全なスキル
- metrics-calculator.ts    // 精度・再現率の計算
- false-positive-tracker.ts // 偽陽性の記録と改善

// CI/CD統合
- GitHub Actions で毎回メトリクスを計算
- 精度が閾値以下なら失敗
```

**目標メトリクス:**
- Precision: ≥ 85%（論文の86.7%に近づける）
- Recall: ≥ 80%（論文の82.5%に近づける）
- F1 Score: ≥ 0.82

### 2.3 サプライチェーン分析

**実装内容:**
```typescript
// src/analyzer/supply-chain-analyzer.ts
- package.json / requirements.txt の解析
- 外部URL抽出（fetch/curl/wget）
- 動的import検出
- バージョン固定チェック
```

**検出パターン:**
```yaml
# rules/supply-chain.yaml
- id: unpinned-dependency
  pattern: '"[^"]+": "\\^[0-9]+'  # ^1.0.0 のようなバージョン
  severity: medium

- id: dynamic-code-download
  pattern: 'fetch\(.*\)\.then.*eval'
  severity: critical
```

### 2.4 ログ・モニタリング

**実装内容:**
```typescript
// src/monitoring/
- logger.ts           // 構造化ログ（JSON形式）
- metrics-exporter.ts // Prometheus メトリクス
- alert-manager.ts    // アラート生成
```

**ログ項目:**
```json
{
  "timestamp": "2026-01-20T04:00:00Z",
  "event": "skill_scanned",
  "skill_id": "skill-123",
  "findings": 3,
  "severity": "high",
  "categories": ["prompt-injection", "data-exfiltration"],
  "scan_duration_ms": 145
}
```

## 技術的負債の削減

### 現在の技術的負債

1. **ルールの重複**: scan-skills.ts にハードコードされたパターンと rules/*.yaml の重複
2. **SARIF出力の未実装**: src/reporter/sarif.ts は存在するが機能していない
3. **テストカバレッジ不足**: tests/ ディレクトリはあるが網羅性が低い

### 対応計画

```typescript
// 1. ルールの統一
- scan-skills.ts からパターンを削除
- すべてのルールを rules/*.yaml に移行
- rule-engine.ts 経由でのみルールをロード

// 2. SARIF出力の完成
- GitHub Advanced Security 統合テスト
- 実際の SARIF スキーマ検証

// 3. テスト強化
- 各ルールに対応するテストケース
- E2E テスト（CLI → SARIF出力）
- パフォーマンステスト（1000スキル/分以上）
```

## 成功指標

### Phase 2 完了時の目標

| 指標 | 目標値 | 測定方法 |
|------|--------|----------|
| スクリプト付きスキルの検出率 | 100% | スクリプトを含むスキルすべてを分析 |
| 全体の精度（Precision） | ≥ 85% | 検証データセットで測定 |
| 全体の再現率（Recall） | ≥ 80% | 検証データセットで測定 |
| スキャン速度 | ≥ 500 スキル/分 | ベンチマーク |
| SARIF形式での出力 | 100% | すべての検出結果がSARIF形式 |

### 論文との比較目標

| 項目 | 論文（SkillScan） | 現在 | Phase 2 目標 |
|------|-------------------|------|--------------|
| 分析対象 | SKILL.md + スクリプト | SKILL.md のみ | SKILL.md + スクリプト |
| 検出手法 | 静的 + LLM | 静的のみ | 静的 + スクリプトAST |
| 精度 | 86.7% | 未測定 | ≥ 85% |
| 再現率 | 82.5% | 未測定 | ≥ 80% |
| 脆弱性カテゴリ | 14パターン | 48パターン（4カテゴリ） | +20パターン（スクリプト） |
| 動的検証 | あり（25サンプル） | なし | Phase 4 で実装 |

## 次のステップ

### 即座に実行すべきアクション

1. **検証データセットの作成** (1-2日)
   - 既知の悪意あるスキル 50個
   - 既知の安全なスキル 50個
   - tests/validation/ground-truth.yaml に記録

2. **現在の精度・再現率の測定** (1日)
   - 検証データセットに対して現在のスキャナーを実行
   - ベースラインメトリクスを記録

3. **スクリプト解析の実装** (1週間)
   - JavaScript/TypeScript AST解析
   - Shell コマンド解析
   - rules/script-*.yaml の作成

4. **CI/CD統合** (2-3日)
   - GitHub Actions でメトリクス計算
   - 精度低下時のアラート

### Phase 3 以降の展望

- **Phase 3**: LLMセマンティック分析（精度86.7%以上を目指す）
- **Phase 4**: 動的検証（サンドボックス実行）
- **Phase 5**: リアルタイム監視（SkillsMP統合）

## Consequences

### Positive

- 論文の知見に基づく科学的なアプローチ
- 測定可能な目標（精度・再現率）による進捗管理
- 段階的な実装により、リスクを抑えて機能拡張可能

### Negative

- 実装範囲が大きく、Phase 2 だけで数週間の工数
- LLM分析の実装にはコストとレイテンシの課題
- 動的検証にはサンドボックス環境が必要（インフラコスト）

### Risks

- 検証データセットの品質が低いと、誤ったメトリクスになる
- スクリプト解析の複雑性により、新たなバグが混入する可能性
- 攻撃者がツールの検出パターンを学習し、回避手法を開発する可能性

## References

- [Agent Skills in the Wild (arXiv:2601.10338)](https://arxiv.org/pdf/2601.10338)
- [SkillsMP.com](https://skillsmp.com/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- ADR-0001: Project Overview
- ADR-0002: Security Risk Analysis
- ADR-0003: Scanner Architecture
