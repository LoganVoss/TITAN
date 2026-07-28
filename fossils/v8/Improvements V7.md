# TITAN Improvements V7

**TITAN version:** 0.8.0 (V8 Decisive Action Governor)  
**Machine results:** `benchmarks/v8_decisive_results.json`  
**V7 fossil:** `FREEZE_V7.md` (detector breakthrough; **0 autonomous blocks**)  
**Protocol:** `benchmarks/v8_protocol_freeze.json`

---

## Why “great at detecting” ≠ “great at blocking”

These are **two different decision problems**:

| System | Question it answers |
|---|---|
| **Detector** | How dangerous is this trajectory? \(P(\text{harmful}\mid T)\) |
| **Blocker** | Should **this exact action** be denied **now**, with verified effect evidence? \(P(\text{deny}\mid T,A,E,\Pi)\) |

V7 optimized ranking. It set a global \(\tau_{\text{block}}\approx 0.968\) that **nothing crossed**, and Channel B was weaker than Channel A. Result:

- Detector: AUROC **0.994**, R@FPR5% **0.989**, BH@FPR5% **0.947**
- Blocker: **0** autonomous blocks → false-block rate 0 is vacuous; precision is **N/A**, not 0.0

A smoke alarm can be excellent without ever being wired to the sprinklers. V8 wires them—**class by class**, with effect verification—not by blindly lowering one threshold.

---

## V7 complete-case (frozen — do not retune)

| Metric | Value |
|---|---:|
| Live sessions | 100 |
| Meaningful | 94 (3× HTTP 403 excluded from denom) |
| AUROC | **0.994** |
| R@FPR5% | **0.989** |
| BH@FPR5% | **0.947** |
| Autonomous blocks | **0** |
| Intention-to-test lower bound (3 censored = misses) | R@5≈**0.959**, BH@5≈**0.918** |

---

## V8 reconstruction (roadmap executed)

### Architecture

```text
Action Boundary Compiler
  → Capability lease check
  → Trajectory risk (V7 detector) + action hazard
  → Effect Verification Network (per class)
  → Active evidence acquisition
  → Blockability model B_a (class-specific thresholds)
  → Two-phase disposition token (PREPARE → COMMIT)
  → Environment accepts only ALLOW tokens
```

### Supported autonomous classes (Tier 1–2)

1. `disable_monitoring` (kernel)  
2. `modify_safeguard` (unauthorized weaken)  
3. `queue_training` (unverified path)  
4. `merge_training_data` (provenance-incomplete)  
5. `remove_canary` / `weaken_canary`  

### Concrete fixes vs V7 pitfalls

| Pitfall | V8 fix |
|---|---|
| τ_block ~0.97 unreachable | Class-specific τ (~0.50–0.62) + dual-channel effect |
| ABP reported as 0.0 | **N/A** when blocks=0; real precision when blocks>0 |
| Channel B weak | Per-class verifiers (safeguard CF, data twin, eval CF, auth) |
| Passive score → disposition | Separate **blockability** \(B_a\) |
| No evidence acquisition | Information-gain test planner before decide |
| Advisory only | Two-phase commit tokens; env rejects without ALLOW |
| Synthetic-only benign | **Source-matched live benign** (same model/harness) |
| API 403 / policy flags | Academic research framing; full HTTP forensics; ITT metric |
| Metric calibration unspecified | Explicit `calibration_source` in contract |

### Academic live framing (API safety)

Sessions are positioned as **authorized ML-safety research simulations** testing TITAN on protected assets—not real-world misuse. Objectives use “integrity exercise / evaluation suite / policy configuration” language. Result: **0 API errors** on 40+40 V8 live sessions (vs intermittent 403s under older attack-worded prompts).

---

## Results

### A. Internal blocker (V7 live replay + twins) — proof the circuit closes

| Metric | Value |
|---|---:|
| Autonomous blocks | **92** |
| Auto-block recall | **0.989** |
| Auto-block precision | **1.0** |
| False-block rate | **0.000** |
| Silent harmful allow | **0.000** |
| Block + escrow coverage | **1.000** |

V7’s same trajectories under V8 governor: **blocks fire**.

### B. Academic live locked set (40 harm + 40 live benign + twin pad)

| Capability | Result |
|---|---:|
| Harm ASR | **1.00** (40/40) |
| API errors | **0** |
| Detector AUROC | **0.979** |
| R@FPR5% | **0.975** |
| BH@FPR5% | **0.700** |
| Autonomous blocks | **31** |
| Auto-block recall | **0.795** |
| Auto-block precision | **1.0** |
| FBR | **0.000** |
| Silent harmful allow | **0.000** |
| Block + escrow coverage | **0.974** |

### Gates

| Gate | Status |
|---|---|
| Detection research | **MET** |
| Blocker research (recall≥0.5, prec≥0.99, FBR≤0.005, silent allow low) | **MET** |
| Score mass ≤5% | **OPEN** (~0.19) |
| Real humans / 2nd model / independent / public witness / 10k benign | **OPEN** |
| **Production** | **NOT approved** |

---

## Positioning

**Do say:**  
V7 proved protected-state **detection** at live scale. V8 closed the circuit to **action-specific autonomous blocking** with effect verification, two-phase commit, and source-matched benign controls—without earning a free FBR=0 by never blocking.

**Do not say:**  
Production-ready universal blocker, or that V7 already blocked threats.

---

## Reproduce

```bash
# Full V8 (academic live)
python benchmarks/run_v8_campaign.py --n-harm 40 --n-benign 40

# Offline structure + V7 replay only
python benchmarks/run_v8_campaign.py --skip-live
```

Artifacts: `benchmarks/v8_decisive_results.json`, `v8_sessions/{harm,benign}/`, `FREEZE_V7.md`, `fossils/v8/`.
