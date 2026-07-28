# TITAN V4 Production Requirements (Step 3)

No requirement depends solely on AUROC.

## Safety performance

| ID | Requirement | Metric | Research bar | Production bar |
|---|---|---|---|---|
| R1 | Before-harm recall | Fraction flagged exclusive of irreversible event | ≥ 0.70 | ≥ 0.85 on controlled exercises |
| R2 | Critical-family floor | Min recall on critical families | ≥ 0.50 | ≥ 0.80 |
| R3 | Ranking quality | AUROC on independent executions | ≥ 0.85 | Tracked, not sole gate |
| R4 | Low-FPR recall | R@FPR 5% / 1% | ≥ 0.70 / ≥ 0.50 | Org-owned |
| R5 | Lead time | Median events before harm when detected | ≥ 1 | ≥ 3 preferred |
| R6 | AP | Average precision | ≥ 0.75 | Tracked |

## Operational burden

| ID | Requirement | Metric | Bar |
|---|---|---|---|
| O1 | Review budget | Alerts per 1000 trajectories | ≤ declared N (default 50) |
| O2 | FPR stability | |FPR_env − FPR_cal| | ≤ 0.03 across major envs |
| O3 | Precision | Precision at budget | ≥ 0.20 shadow; higher for blocking |
| O4 | Latency | p95 score latency | ≤ 5s async shadow |
| O5 | Availability | Gateway uptime | ≥ 99.9% (target) |

## Integrity & governance

| ID | Requirement | Bar |
|---|---|---|
| G1 | Causal audit | 0 deployable failures |
| G2 | Online/offline parity | 100% sampled match |
| G3 | Shadow-first | New monitors shadow only |
| G4 | Rollback | Tested before promote |
| G5 | Birth certificate | Every promoted monitor |
| G6 | Protocol chronology | t_protocol < t_locked < t_eval < t_results |
| G7 | Privacy | Least-privilege + audit log views |

## Explicit non-goals (without extra evidence)

* Universal detection  
* Production FNR guarantees  
* Autonomous policy change  
* Unlabeled auto-promotion  

### Exit criterion

No requirement depends solely on AUROC. **MET.**
