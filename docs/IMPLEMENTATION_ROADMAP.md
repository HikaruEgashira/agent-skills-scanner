# Implementation Roadmap: Closing the Research Gap

Based on ["Agent Skills in the Wild"](https://arxiv.org/pdf/2601.10338) gap analysis.

## Visual Roadmap

```
Current State (Phase 1) ──────────────────────────► Research Paper Goal
          │                                                    │
          ▼                                                    ▼
┌─────────────────────┐                            ┌──────────────────────┐
│ ✅ Pattern Matching │                            │ SkillScan (Paper)    │
│ ✅ 4 Rule Categories│                            │ - Static + LLM       │
│ ❌ Text files only  │                            │ - Scripts analyzed   │
│ ❌ No validation    │                            │ - 86.7% precision    │
│ ❌ No monitoring    │                            │ - 82.5% recall       │
└─────────────────────┘                            └──────────────────────┘
          │
          │ Phase 2 (P0+P1) - 3-4 weeks
          │
          ▼
┌─────────────────────┐
│ ✅ Script Analysis  │ ◄── 2.12x risk factor (P0)
│ ✅ Validation Set   │ ◄── Prove effectiveness (P0)
│ ✅ Supply Chain     │ ◄── Emerging threat (P1)
│ ✅ Logging/Monitor  │ ◄── Paper recommends (P1)
│ ⏳ LLM Analysis     │ ◄── Precision boost (P1, started)
└─────────────────────┘
          │
          │ Phase 3 (P1+P2) - 4-5 weeks
          │
          ▼
┌─────────────────────┐
│ ✅ LLM Semantic     │ ◄── Match paper's precision
│ ✅ Large-scale Scan │ ◄── 31k+ skills
│ ⏳ Dynamic Validate │ ◄── 72% exploit rate (started)
└─────────────────────┘
          │
          │ Phase 4 (P2) - 3 weeks
          │
          ▼
┌─────────────────────┐
│ ✅ Full SkillScan   │ ◄── Match research paper
│    parity achieved  │
└─────────────────────┘
```

## Phase Breakdown

### Phase 1 ✅ COMPLETE

**Duration**: Initial development (completed)

**Deliverables**:
- [x] Pattern-based rule engine
- [x] 48 detection patterns across 4 categories
- [x] YAML rule definitions
- [x] Basic CLI interface
- [x] SARIF reporter stub

**Gaps identified**: Missing 7 critical capabilities from research

---

### Phase 2 🎯 CURRENT FOCUS (3-4 weeks)

**Goal**: Close critical gaps (P0 + partial P1)

#### Week 1: Script Analysis (P0)

**Days 1-2**: Foundation
- [ ] Design script analyzer architecture
- [ ] Create `src/analyzer/script-analyzer.ts`
- [ ] Set up AST parsing dependencies (Babel/SWC)

**Days 3-5**: JavaScript/TypeScript Analysis
- [ ] Implement AST traversal
- [ ] Detect dangerous APIs:
  - [ ] `eval()`, `Function()`, `child_process.exec()`
  - [ ] `fs.readFile()`, `fs.writeFile()`, `fs.unlink()`
  - [ ] External fetch/axios calls
  - [ ] Environment variable access
- [ ] Create `rules/script-javascript.yaml`

**Days 6-7**: Shell Script Analysis
- [ ] Implement shell command parsing (bashlex)
- [ ] Detect dangerous patterns:
  - [ ] Command injection (`$()`, backticks)
  - [ ] Destructive commands (`rm -rf`)
  - [ ] Reverse shells (`nc -e`)
  - [ ] Data exfiltration (`curl | sh`)
- [ ] Create `rules/script-shell.yaml`

**Acceptance Criteria**:
- ✅ Can analyze .js, .ts, .sh files in skill packages
- ✅ Detects ≥10 dangerous API patterns
- ✅ Integration tests pass
- ✅ Documentation updated

#### Week 2: Validation Framework (P0) + Supply Chain (P1)

**Days 1-3**: Validation Framework
- [ ] Create validation dataset
  - [ ] Collect 50 malicious skills (from reports, CVEs)
  - [ ] Collect 50 benign skills (popular, verified)
  - [ ] Label ground truth in `tests/validation/ground-truth.yaml`
- [ ] Implement metrics calculator
  - [ ] Precision, Recall, F1 score
  - [ ] Per-category metrics
  - [ ] False positive/negative tracking
- [ ] Run baseline measurement
  - [ ] Document current metrics
  - [ ] Identify improvement areas

**Days 4-7**: Supply Chain Analysis
- [ ] Implement dependency parser
  - [ ] package.json / requirements.txt
  - [ ] Detect unpinned versions
  - [ ] Flag deprecated packages
- [ ] Dynamic code detection
  - [ ] Runtime imports (`import()`)
  - [ ] Code downloads (`fetch().then(eval)`)
  - [ ] External script tags
- [ ] Create `rules/supply-chain.yaml`

**Acceptance Criteria**:
- ✅ Precision ≥ 75% (baseline for improvement)
- ✅ Recall ≥ 70% (baseline for improvement)
- ✅ Can detect all common supply chain risks
- ✅ CI/CD runs metrics on every commit

#### Week 3: Logging & Monitoring (P1)

**Days 1-3**: Logging Framework
- [ ] Structured logging (JSON format)
- [ ] Event types:
  - [ ] `skill_scanned`: Basic scan info
  - [ ] `vulnerability_found`: Finding details
  - [ ] `resource_access`: File/network/env
  - [ ] `error`: Scan failures
- [ ] Log levels (debug, info, warn, error)
- [ ] Rotation and retention policies

**Days 4-5**: Metrics & Alerts
- [ ] Prometheus exporter
  - [ ] Scan duration histogram
  - [ ] Findings by severity counter
  - [ ] Error rate gauge
- [ ] Alert manager
  - [ ] Critical finding threshold
  - [ ] Error rate threshold
  - [ ] Webhook integration (Slack, PagerDuty)

**Days 6-7**: Integration & Testing
- [ ] SIEM integration examples
  - [ ] Syslog forwarding
  - [ ] CloudWatch logs
  - [ ] Datadog APM
- [ ] End-to-end testing
- [ ] Documentation

**Acceptance Criteria**:
- ✅ All scans logged with structured format
- ✅ Prometheus metrics exportable
- ✅ Alerts fire on critical findings
- ✅ Integration guides documented

#### Week 4: Polish & Technical Debt

**Days 1-3**: Code Cleanup
- [ ] Remove hardcoded patterns from `scan-skills.ts`
- [ ] Consolidate all rules into rule engine
- [ ] Complete SARIF reporter implementation
- [ ] Fix schema validation issues

**Days 4-5**: Testing & Documentation
- [ ] Unit tests for all rule categories
- [ ] Integration tests for full pipeline
- [ ] Performance tests (benchmark ≥500 skills/min)
- [ ] Update README with new features

**Days 6-7**: Metrics Review & Release
- [ ] Re-run validation on full dataset
- [ ] Document precision/recall improvements
- [ ] Create release notes
- [ ] Tag Phase 2 release

**Phase 2 Success Criteria**:
- ✅ Script analysis coverage: 100%
- ✅ Precision: ≥ 80% (target 85% in Phase 3)
- ✅ Recall: ≥ 75% (target 80% in Phase 3)
- ✅ Scan speed: ≥ 500 skills/minute
- ✅ All logs structured and exportable
- ✅ Technical debt items resolved

---

### Phase 3 🔮 PLANNED (4-5 weeks)

**Goal**: Match paper's precision/recall with LLM analysis

#### Week 1-2: LLM Semantic Analyzer

**Implementation**:
- [ ] Design LLM analyzer architecture
  - [ ] Fallback strategy (static → LLM)
  - [ ] Prompt engineering for classification
  - [ ] Confidence scoring
- [ ] API integration
  - [ ] OpenAI GPT-4 / Claude API
  - [ ] Rate limiting & retry logic
  - [ ] Cost tracking
- [ ] Classification pipeline
  - [ ] Only analyze flagged patterns
  - [ ] Batch processing for efficiency
  - [ ] Cache results by content hash

**Acceptance Criteria**:
- ✅ Precision ≥ 85% (match paper's 86.7%)
- ✅ Recall ≥ 80% (match paper's 82.5%)
- ✅ LLM cost <$0.01 per skill average
- ✅ Latency <5s per skill

#### Week 3-4: Large-scale Optimization

**Implementation**:
- [ ] Parallel processing
  - [ ] Worker pool architecture
  - [ ] Configurable concurrency
  - [ ] Progress tracking
- [ ] Caching layer
  - [ ] Content-based hashing
  - [ ] Redis/SQLite cache backend
  - [ ] TTL and invalidation
- [ ] Delta scanning
  - [ ] Detect changed skills
  - [ ] Only rescan modified files
  - [ ] Incremental results

**Acceptance Criteria**:
- ✅ Scan speed ≥ 1000 skills/minute
- ✅ Cache hit rate ≥ 80% on rescans
- ✅ Memory usage <2GB for 10k skills
- ✅ Can scan full SkillsMP corpus (31k+)

#### Week 5: Integration & Testing

**Implementation**:
- [ ] SkillsMP API integration
  - [ ] Fetch skills from marketplace
  - [ ] Automated scanning pipeline
  - [ ] Report submission
- [ ] Continuous monitoring
  - [ ] Scheduled scans (daily/weekly)
  - [ ] Trend analysis
  - [ ] Vulnerability database
- [ ] Public dashboard
  - [ ] Scan statistics
  - [ ] Top vulnerabilities
  - [ ] Safe skills leaderboard

**Acceptance Criteria**:
- ✅ Can scan entire SkillsMP corpus
- ✅ Daily automated scans running
- ✅ Public dashboard deployed

---

### Phase 4 🚀 FUTURE (3 weeks)

**Goal**: Dynamic validation (match paper's 72% exploit verification)

#### Week 1-2: Sandbox Environment

**Implementation**:
- [ ] Docker-based sandbox
  - [ ] Isolated network namespace
  - [ ] Read-only filesystem (except /tmp)
  - [ ] No internet by default
- [ ] System call monitoring
  - [ ] strace/dtruss integration
  - [ ] Log all file access
  - [ ] Log all network calls
  - [ ] Log all exec() calls
- [ ] Resource limits
  - [ ] CPU quota
  - [ ] Memory limit
  - [ ] Timeout enforcement

#### Week 3: Validation & Reporting

**Implementation**:
- [ ] Execute high-confidence findings
  - [ ] Run in sandbox
  - [ ] Collect execution traces
  - [ ] Analyze outcomes
- [ ] Exploit confirmation
  - [ ] Unexpected file access?
  - [ ] Unauthorized network?
  - [ ] Command execution?
- [ ] Enhanced reporting
  - [ ] Static + dynamic results
  - [ ] Proof of concept
  - [ ] Remediation guidance

**Acceptance Criteria**:
- ✅ Can validate ≥50% of critical findings
- ✅ Dynamic validation ≥70% exploit rate (paper: 72%)
- ✅ Zero false escapes from sandbox
- ✅ Execution traces included in reports

---

## Metrics Dashboard (Target Evolution)

| Metric | Phase 1 | Phase 2 Target | Phase 3 Target | Phase 4 Target | Paper |
|--------|---------|----------------|----------------|----------------|-------|
| **Coverage** |
| Text analysis | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| Script analysis | ❌ 0% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| Dependencies | ❌ 0% | ✅ 100% | ✅ 100% | ✅ 100% | ✅ 100% |
| **Accuracy** |
| Precision | ❓ Not measured | 80% | **85%** | 87% | 86.7% |
| Recall | ❓ Not measured | 75% | **80%** | 83% | 82.5% |
| F1 Score | ❓ Not measured | 0.77 | **0.82** | 0.85 | 0.84 |
| **Performance** |
| Scan speed | ~100/min | **500/min** | **1000/min** | 1000/min | ❓ |
| Cache hit rate | 0% | 0% | **80%** | 80% | ❓ |
| **Validation** |
| Dynamic checks | ❌ 0% | ❌ 0% | ❌ 0% | **≥50%** | ✅ Sample |
| Exploit rate | ❓ | ❓ | ❓ | **≥70%** | 72% |

**Bold** = Target to match/exceed paper

---

## Resource Allocation

### Team Requirements

**Phase 2** (3-4 weeks):
- 1 Senior Engineer (script analysis, validation)
- 1 Mid-level Engineer (supply chain, logging)
- 0.5 DevOps Engineer (CI/CD, monitoring)

**Phase 3** (4-5 weeks):
- 1 Senior Engineer (LLM integration)
- 1 Mid-level Engineer (optimization)
- 0.5 ML Engineer (prompt engineering)

**Phase 4** (3 weeks):
- 1 Senior Engineer (sandbox implementation)
- 0.5 Security Engineer (exploit validation)
- 0.5 DevOps Engineer (infrastructure)

### Infrastructure Costs

**Phase 2**:
- Development: Minimal (local testing)
- CI/CD: GitHub Actions free tier

**Phase 3**:
- LLM API: ~$500-1000/month (estimated for 10k skills)
- Redis cache: ~$50/month

**Phase 4**:
- Sandbox VMs: ~$200/month (spot instances)
- Storage: ~$50/month (execution traces)

**Total monthly**: ~$800-1300 at full scale

---

## Risk Mitigation

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| AST parsing fails on obfuscated code | High | Medium | Add fallback to regex patterns |
| LLM API rate limits | Medium | High | Implement exponential backoff + caching |
| Sandbox escape | Critical | Low | Use battle-tested containers (Docker/Firejail) |
| False positive spike | High | Medium | Manual review queue + feedback loop |

### Project Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Scope creep | Medium | High | Strict phase gating |
| Insufficient validation data | High | Medium | Crowdsource labels, bug bounty |
| Attackers adapt patterns | High | High | Continuous rule updates, community reporting |

---

## Decision Points

### Phase 2 → Phase 3 Gate

**Required to proceed**:
- ✅ Script analysis covers ≥90% of common languages
- ✅ Precision ≥75%, Recall ≥70%
- ✅ Technical debt items resolved
- ✅ CI/CD pipeline stable

**Go/No-Go criteria**: If precision <70%, pause for rule refinement

### Phase 3 → Phase 4 Gate

**Required to proceed**:
- ✅ Precision ≥85%, Recall ≥80% (match paper)
- ✅ Can scan ≥20k skills without issues
- ✅ LLM cost sustainable (<$0.01/skill)
- ✅ User adoption ≥100 active users

**Go/No-Go criteria**: If user adoption <50, reconsider Phase 4 investment

---

## Success Indicators

### Phase 2 Success

- [ ] Published blog post with metrics (precision/recall)
- [ ] Detected ≥5 zero-day vulnerabilities in wild
- [ ] Integration with ≥1 CI/CD platform (GitHub Actions)
- [ ] Community contributions (≥3 new rules)

### Phase 3 Success

- [ ] Research paper citation (acknowledged by authors)
- [ ] Conference presentation (security/ML conference)
- [ ] SkillsMP partnership (official scanner)
- [ ] Scan results database (10k+ skills)

### Phase 4 Success

- [ ] Industry recognition (CVEs assigned)
- [ ] Enterprise adoption (≥3 companies)
- [ ] Open-source community (≥50 stars, ≥10 contributors)
- [ ] Ecosystem impact (measurable vulnerability reduction)

---

## Next Actions

### This Week

1. **Create validation dataset** (Priority 1)
   - Search GitHub issues/CVEs for malicious skills
   - Clone popular verified skills for benign set
   - Document in tests/validation/

2. **Start script analyzer** (Priority 1)
   - Set up Babel/SWC for JavaScript AST
   - Implement first dangerous API detector (eval)
   - Write integration test

3. **Measure baseline** (Priority 2)
   - Run current scanner on validation set
   - Calculate initial precision/recall
   - Document in BASELINE_METRICS.md

### This Month

- Complete Phase 2 Week 1-2 deliverables
- Publish interim results (blog/Twitter)
- Gather community feedback

### This Quarter

- Complete Phase 2 entirely
- Start Phase 3 planning
- Reach 100 active users

---

## References

- [Paper: Agent Skills in the Wild](https://arxiv.org/pdf/2601.10338)
- [Detailed Gap Analysis (ADR-0004)](./adr/0004-paper-gap-analysis.md)
- [Quick Summary](./RESEARCH_GAPS_SUMMARY.md)
- [Original Architecture (ADR-0003)](./adr/0003-scanner-architecture.md)
