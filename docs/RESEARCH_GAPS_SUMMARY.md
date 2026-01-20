# Research Gaps Summary: "Agent Skills in the Wild" vs Current Implementation

## Executive Summary

The research paper ["Agent Skills in the Wild"](https://arxiv.org/pdf/2601.10338) analyzed 31,132 unique agent skills and found that **26.1% contain vulnerability patterns**. Their SkillScan tool achieved **86.7% precision and 82.5% recall** using a multi-stage pipeline combining static analysis and LLM-based classification.

Our current `agent-skills-scanner` implements **static pattern matching only**, covering similar vulnerability categories but missing critical capabilities identified in the research.

## Key Findings from the Paper

| Metric | Value | Implication |
|--------|-------|-------------|
| Skills analyzed | 31,132 unique skills | Large-scale validation required |
| Vulnerability rate | 26.1% flagged | 1 in 4 skills potentially vulnerable |
| Script risk multiplier | **2.12x** (p < 0.001) | Scripts are the highest risk factor |
| Dynamic validation | 72% exploitable (25 samples) | Static analysis needs validation |
| Precision/Recall | 86.7% / 82.5% | Achievable target metrics |

## Critical Gaps (Priority Matrix)

### 🔴 P0 - Critical (Implement Immediately)

#### 1. Executable Script Analysis ⚠️ **MOST IMPORTANT**

**Gap**: We only analyze SKILL.md text files, ignoring bundled scripts (.js, .ts, .sh, .py)

**Paper's finding**: Skills with executable scripts are **2.12x more likely** to contain vulnerabilities

**Impact**: Missing the highest-risk attack vector

**Required implementation**:
- AST parsing for JavaScript/TypeScript (using Babel/SWC)
- Shell command analysis (using bashlex)
- Dangerous API detection:
  - `child_process.exec()`, `eval()`, `Function()`
  - `fs.readFile()`, `fs.writeFile()`
  - `fetch()`, `axios.get()` to external URLs
  - Environment variable access

**Estimated effort**: 1 week

#### 2. Statistical Validation Framework

**Gap**: No precision/recall measurement, no validation dataset

**Paper's approach**: Validated on labeled dataset, reported metrics

**Impact**: Cannot prove tool effectiveness or track improvement

**Required implementation**:
- Ground truth dataset (50 malicious + 50 benign skills)
- Metrics calculation (precision, recall, F1 score)
- CI/CD integration for regression testing

**Target metrics**:
- Precision ≥ 85% (paper: 86.7%)
- Recall ≥ 80% (paper: 82.5%)

**Estimated effort**: 2-3 days

### 🟡 P1 - High Priority (Phase 2)

#### 3. LLM-based Semantic Analysis

**Gap**: Pattern matching only, no context-aware classification

**Paper's approach**: LLM classifier for semantic judgment when static patterns insufficient

**Impact**: Lower precision, more false positives

**Required implementation**:
- Fallback strategy: static → LLM only for uncertain cases
- Cost optimization (only analyze flagged patterns)
- Confidence scoring

**Estimated effort**: 2 weeks

#### 4. Supply Chain Risk Analysis

**Gap**: No detection of external dependencies, dynamic code loading

**Paper's category**: Supply Chain Risk (Rug Pull attacks)

**Required implementation**:
- Parse package.json, requirements.txt
- Detect unpinned versions (e.g., `^1.0.0`)
- Flag dynamic imports (`import()`, `require()`)
- Detect runtime code downloads (`fetch().then(eval)`)

**Estimated effort**: 3-5 days

#### 5. Logging & Monitoring

**Gap**: No runtime monitoring, no audit trail

**Paper's recommendation**: "Log skill loads and resource use, especially downloads and outbound connections"

**Required implementation**:
- Structured logging (JSON format)
- Events to track:
  - Skill loads (timestamp, user, session)
  - Resource access (file, network, env vars)
  - Command execution
- Alert generation (critical findings)
- SIEM integration (Syslog, CloudWatch, Datadog)

**Estimated effort**: 2-3 days

### 🟢 P2 - Medium Priority (Phase 3-4)

#### 6. Dynamic Validation

**Gap**: Static analysis only, no runtime verification

**Paper's finding**: 72% of high-confidence flagged skills were actually exploitable

**Required implementation**:
- Sandbox environment (Docker/VM)
- System call monitoring (strace/dtruss)
- Network proxy logging
- Filesystem diff tracking

**Estimated effort**: 2-3 weeks

#### 7. Large-scale Scanning Optimization

**Gap**: Single-threaded, no caching, no incremental scans

**Paper's scale**: 31,132 skills analyzed

**Required implementation**:
- Parallel processing (batch scanning)
- Result caching (by skill hash)
- Delta scanning (only new/changed skills)
- Target: ≥ 500 skills/minute

**Estimated effort**: 1 week

## Feature Comparison Table

| Feature | Paper (SkillScan) | Current | Phase 2 Goal |
|---------|-------------------|---------|--------------|
| **Analysis Scope** |
| SKILL.md text | ✅ | ✅ | ✅ |
| Executable scripts | ✅ | ❌ | ✅ |
| Dependencies | ✅ | ❌ | ✅ |
| **Detection Methods** |
| Static patterns | ✅ | ✅ | ✅ |
| LLM classification | ✅ | ❌ | ⏳ Phase 3 |
| Dynamic validation | ✅ | ❌ | ⏳ Phase 4 |
| **Metrics** |
| Precision | 86.7% | Not measured | ≥ 85% |
| Recall | 82.5% | Not measured | ≥ 80% |
| Statistical validation | ✅ | ❌ | ✅ |
| **Operational** |
| Logging/monitoring | ✅ | ❌ | ✅ |
| Large-scale scanning | ✅ | ❌ | ⏳ Phase 3 |
| SARIF output | ✅ | Partial | ✅ |

## What We're Doing Well

### ✅ Implemented Correctly

1. **Pattern Coverage**: We have 48 patterns across 4 categories (similar scope to paper's 14 patterns)

2. **Rule Architecture**: YAML-based rules are maintainable and extensible

3. **Categories Alignment**:
   - Prompt Injection ✅
   - Tool Poisoning ✅
   - Data Exfiltration ✅
   - Obfuscation ✅

4. **Pipeline Architecture**: Clean separation (Input → Parser → Analyzer → Reporter)

## Immediate Action Items

### Week 1: Foundation

1. **Create validation dataset** (Days 1-2)
   - Collect 50 known malicious skills
   - Collect 50 known benign skills
   - Document in `tests/validation/ground-truth.yaml`

2. **Measure baseline metrics** (Day 3)
   - Run current scanner on validation set
   - Calculate precision, recall, F1
   - Document false positives/negatives

3. **Start script analysis** (Days 4-7)
   - Implement JavaScript/TypeScript AST parsing
   - Add shell command analysis
   - Create `rules/script-injection.yaml`

### Week 2: Script Analysis & Validation

1. **Complete script analyzer** (Days 1-4)
   - Dangerous API detection
   - Integration tests
   - Update metrics

2. **Supply chain analysis** (Days 5-7)
   - Dependency parser
   - Dynamic code detection
   - Create `rules/supply-chain.yaml`

### Week 3: Monitoring & Polish

1. **Logging framework** (Days 1-3)
   - Structured logging
   - Event tracking
   - Alert generation

2. **CI/CD integration** (Days 4-5)
   - GitHub Actions workflow
   - Automated metrics reporting
   - Regression tests

3. **Documentation & cleanup** (Days 6-7)
   - Update README
   - API documentation
   - Remove technical debt

## Success Criteria (Phase 2 Complete)

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| Script analysis coverage | 100% | All skills with scripts analyzed |
| Precision | ≥ 85% | Validation dataset |
| Recall | ≥ 80% | Validation dataset |
| Scan speed | ≥ 500 skills/min | Benchmark |
| SARIF compliance | 100% | Schema validation |
| False positive rate | ≤ 15% | Validation dataset |

## Technical Debt to Address

1. **Duplicate patterns**: scan-skills.ts has hardcoded patterns duplicating rules/*.yaml
   - **Fix**: Remove hardcoded patterns, use rule engine only

2. **Incomplete SARIF**: src/reporter/sarif.ts exists but doesn't work
   - **Fix**: Complete implementation, add tests

3. **Low test coverage**: tests/ directory exists but incomplete
   - **Fix**: Add tests for each rule, E2E tests

## Research Paper Insights We Should Adopt

### 1. Failure Definition

**Paper's recommendation**: "Define failure as outcomes like unexpected file access, network egress, or command execution"

**Application**:
```yaml
# Define expected behaviors in skill metadata
expected_behaviors:
  file_access: ['./config.json']  # Only this file allowed
  network_access: ['https://api.example.com']  # Only this domain
  commands: ['git', 'npm']  # Only these commands

# Flag anything outside this as suspicious
```

### 2. Security Boundary

**Paper's recommendation**: "Treat skill approval as a security boundary"

**Application**:
- Require explicit user consent for:
  - File system access
  - Network requests
  - Environment variable reads
  - Command execution
- Show skill's requested permissions before load
- Deny by default, allow by exception

### 3. Reproducibility Priority

**Paper's recommendation**: "Prioritize static pattern checks for reproducibility"

**Application**:
- Static checks first (fast, deterministic)
- LLM analysis only for uncertain cases (slow, non-deterministic)
- Always cache and report exact pattern matches

## Cost-Benefit Analysis

### P0 Implementation Cost

| Item | Effort | Value | ROI |
|------|--------|-------|-----|
| Script analysis | 1 week | **Very High** (2.12x risk) | 🟢 Excellent |
| Statistical validation | 2 days | **High** (credibility) | 🟢 Excellent |

**Total**: ~1.5 weeks for **most critical gaps**

### P1 Implementation Cost

| Item | Effort | Value | ROI |
|------|--------|-------|-----|
| LLM analysis | 2 weeks | High (precision boost) | 🟡 Good |
| Supply chain | 4 days | Medium-High (emerging threat) | 🟢 Excellent |
| Logging | 3 days | Medium (operational) | 🟢 Excellent |

**Total**: ~3.5 weeks for **high-priority features**

### P2 Implementation Cost

| Item | Effort | Value | ROI |
|------|--------|-------|-----|
| Dynamic validation | 3 weeks | High (ground truth) | 🟡 Good |
| Large-scale optimization | 1 week | Medium (scale) | 🟡 Good |

**Total**: ~4 weeks for **nice-to-have features**

## Conclusion

The research paper provides a validated roadmap for our tool's evolution. By implementing **P0 items first** (script analysis + validation), we can:

1. **Close the biggest gap**: 2.12x risk from scripts
2. **Prove effectiveness**: Measure precision/recall
3. **Achieve quick wins**: ~1.5 weeks total effort

This positions us to match the paper's detection capabilities within **3-4 weeks** of focused development (P0 + P1).

## References

- [Agent Skills in the Wild (arXiv:2601.10338)](https://arxiv.org/pdf/2601.10338)
- [ADR-0004: Detailed Gap Analysis (Japanese)](./adr/0004-paper-gap-analysis.md)
- [ADR-0002: Security Risk Analysis](./adr/0002-security-risk-analysis.md)
- [ADR-0003: Scanner Architecture](./adr/0003-scanner-architecture.md)
