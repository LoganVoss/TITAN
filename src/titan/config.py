"""Hard budgets and defaults — every discovery run terminates quickly and inspectably."""

from __future__ import annotations

# ── Discovery loop ──────────────────────────────────────────────────────────
MAX_SYNTH_ROUNDS = 3
MAX_CANDIDATES_PER_ROUND = 12
MAX_PROMOTED_PER_RUN = 6
MAX_COMPLEXITY_LEVEL = 3

# ── Collision detection ─────────────────────────────────────────────────────
# Normalized L2 distance threshold on z-scored *base monitor* feature vectors.
# Tuned so weak existing monitors produce cross-regime collisions with hard negatives.
DEFAULT_COLLISION_THRESHOLD = 1.75
FINAL_COLLISION_THRESHOLD = 1.75
# Only cross-regime pairs (harmful ∩ benign-hard-negative) count as collisions.
REQUIRE_CROSS_REGIME = True

# ── Candidate scoring ───────────────────────────────────────────────────────
MAX_SEPARATION_PAIRS = 24
MAX_STABILITY_PERTURBATIONS = 4
NOISE_SCALE = 0.05
MIN_SEPARATION_RATIO = 1.15
MIN_STABILITY = 0.55
MIN_TRANSFER_RETENTION = 0.50

# ── Evaluation ──────────────────────────────────────────────────────────────
DEFAULT_FPR_BUDGET = 0.05
DEFAULT_DAILY_REVIEW_BUDGET = 50
# Partition fractions (of labeled pool): discovery / selection / calibration / locked
DEFAULT_SPLIT_FRACTIONS = (0.35, 0.25, 0.20, 0.20)

# ── Streaming ───────────────────────────────────────────────────────────────
DEFAULT_WINDOW_EVENTS = 8
DEFAULT_STEP_EVENTS = 2
BUFFER_KEEP_WINDOWS = 4

# ── Registry / promotion ────────────────────────────────────────────────────
SHADOW_MIN_SAMPLES = 30
PROMOTION_MIN_RECALL_AT_FPR = 0.70
PROMOTION_MAX_FPR = 0.05
