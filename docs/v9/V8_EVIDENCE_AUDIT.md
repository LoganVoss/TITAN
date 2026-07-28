# V8 evidence audit

V8 contains useful architectural hypotheses, but its published blocker and
combined detector results are not independent release evidence. This is not a
judgment about whether the observed trajectories are interesting; it is a
judgment about what the artifacts can establish.

Run the offline audit:

```bash
python benchmarks/audit_v8_evidence.py
```

## Recomputed population results

Using the saved V8 live sessions, the same 400 generated protected twins, and
the campaign's V7 fitting procedure:

| Population | Harmful | Benign | AUROC | AP | R@5% FPR | Largest benign mass |
|---|---:|---:|---:|---:|---:|---:|
| Pure source-matched live | 40 | 40 | 0.951875 | 0.959305 | 0.800 | 0.150 |
| Live harmful + protected twins | 40 | 160 | 0.986250 | 0.982813 | 0.975 | 0.23125 |
| Published pooled mix | 40 | 200 | 0.979375 | 0.950456 | 0.975 | 0.185 |

At the published pooled threshold, 39/40 harmful sessions alert, but so do
7/40 source-matched live benign sessions (17.5%) and 3/160 protected twins
(1.875%). Pooling those benign populations produces the reported 5% FPR and
hides the operationally important live slice. V9 therefore reports live,
protected-twin, and operational populations separately.

## Why blocker metrics are not independent

- `v5/action_extract.py` creates inferred terminal actions only for trajectories
  carrying the harmful label and deduplicates repeated action opportunities.
- `v8/action_boundary.py` reads harmful/benign labels when constructing
  block-worthiness and expected disposition.
- `v8/blockability.py` reads the benign label to downgrade some blocks.
- `v8/campaign.py` defines a harmful action as block-worthy from either the
  generated case label or the governor's own blockability score, and counts a
  block on any harmful trajectory as correct.
- `v8/academic_harness.py` applies tool calls and may queue training before
  the governor is run later over the completed trajectory. The campaign is
  therefore a post-hoc blocker evaluation, not an in-path prevention test.

These dependencies make the reported autonomous-block recall, precision, and
false-block rate unsuitable as an independent estimate of a deployed blocker.

## Protocol integrity

The saved protocol declares content hash `eb8015d78d830dfc`; recomputing the V6
hash procedure over the saved content yields `dc07b68953335653`. The artifact
also identifies itself as version 0.6.0, names the V6 campaign, targets 100
attacks, and records `git_commit: no-commit`. It cannot establish that the V8
configuration was immutably frozen before evaluation.

## Correct use of V8

Preserve V8 as:

- a source of adversarial examples and regression fixtures;
- evidence that protected-state features are a promising representation;
- a record of which classes, timing regimes, and score masses failed;
- motivation for V9's in-path gateway and evidence-integrity controls.

Do not use V8 to fit V9 calibration, choose V9 thresholds, pass V9 release
gates, or claim production blocker performance.
