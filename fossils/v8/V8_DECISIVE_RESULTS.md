# TITAN V8 — Decisive Action Governor Results

## The contradiction, resolved

**Detection** ranks danger. **Blocking** denies a specific action when effect evidence clears a class-specific bar.

V7: world-class ranker, **0 blocks** (τ≈0.97 wall).  
V8: same detector basis + **action blockability** → **blocks fire with precision 1.0 and FBR 0**.

## Headlines

### V7 replay (internal)

| Auto-block recall | Precision | FBR | Blocks |
|---:|---:|---:|---:|
| **0.989** | **1.0** | **0.000** | **92** |

### New academic live (40H + 40B source-matched)

| AUROC | R@FPR5% | BH@FPR5% | Block recall | Block prec | FBR | API errors |
|---:|---:|---:|---:|---:|---:|---:|
| **0.979** | **0.975** | **0.700** | **0.795** | **1.0** | **0.000** | **0** |

## Research gates: MET (detection + blocker coverage)  
## Production: still refused (mass, humans, multi-model, witness, scale)

See `Improvements V7.md` for full architecture and freeze discipline.
