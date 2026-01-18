# Architecture Decision Records

このディレクトリには、Agent Skills Scannerプロジェクトのアーキテクチャ決定記録（ADR）が含まれています。

## ADRとは

Architecture Decision Records（ADR）は、ソフトウェアアーキテクチャに関する重要な決定を記録するための軽量なドキュメントです。各ADRは、決定の背景、決定内容、およびその結果を記述します。

## ADR一覧

| ID | タイトル | Status | Date |
|----|----------|--------|------|
| [ADR-0001](./0001-project-overview.md) | プロジェクト概要と目的 | Accepted | 2026-01-18 |
| [ADR-0002](./0002-security-risk-analysis.md) | セキュリティリスク分析 | Accepted | 2026-01-18 |
| [ADR-0003](./0003-scanner-architecture.md) | スキャナーアーキテクチャ設計 | Accepted | 2026-01-18 |

## ADRのステータス

- **Proposed**: 提案中、レビュー待ち
- **Accepted**: 承認済み、実装対象
- **Deprecated**: 非推奨、別のADRに置き換え
- **Superseded**: 廃止、新しいADRで上書き

## 新しいADRの追加方法

1. `NNNN-title.md`形式で新しいファイルを作成（NNNNは連番）
2. [MADR](https://adr.github.io/madr/)フォーマットに従って記述
3. この`README.md`のADR一覧に追加
4. PRを作成してレビューを受ける

## 参考リンク

- [ADR GitHub Organization](https://adr.github.io/)
- [MADR - Markdown ADR](https://adr.github.io/madr/)
