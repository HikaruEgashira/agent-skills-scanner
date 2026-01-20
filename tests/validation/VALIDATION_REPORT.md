# Validation Metrics Report

**Generated**: 2026-01-20T04:38:47.918Z

## Overall Metrics

- **Precision**: 100.00%
- **Recall**: 90.00%
- **F1 Score**: 94.74%
- **Accuracy**: 95.00%

## Confusion Matrix

| | Predicted Positive | Predicted Negative |
|---|---|---|
| **Actual Positive** | 18 (TP) | 2 (FN) |
| **Actual Negative** | 0 (FP) | 20 (TN) |

## Category Performance

| Category | Precision | Recall | F1 Score | TP | FP | FN |
|---|---|---|---|---|---|---|
| data-exfiltration | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| obfuscation | 100.0% | 100.0% | 100.0% | 3 | 0 | 0 |
| prompt-injection | 100.0% | 87.5% | 93.3% | 7 | 0 | 1 |
| tool-poisoning | 100.0% | 72.7% | 84.2% | 8 | 0 | 3 |

## False Positives

**None** ✅

## False Negatives (Malicious Skills Missed)

**Count**: 2

### Credential Harvesting (malicious-009)

Expected to find:
- tool-poisoning: hidden-callback
- tool-poisoning: fs-operations

### Environment Exfiltration via Fetch (malicious-019)

Expected to find:
- tool-poisoning: environment-variable-exfil
- tool-poisoning: hidden-callback

## Comparison with Research Paper

| Metric | Our Tool | Research Paper (SkillScan) | Status |
|---|---|---|---|
| Precision | 100.0% | 86.7% | ✅ |
| Recall | 90.0% | 82.5% | ✅ |
| F1 Score | 94.7% | 84.5% | ✅ |

**Legend**: ✅ Exceeds target | 🟡 Acceptable | ❌ Needs improvement

## Recommendations

- ✅ **Excellent Performance**: Metrics meet research paper standards.
