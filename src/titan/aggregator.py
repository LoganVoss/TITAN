"""
Phase 5 — Sparse transparent aggregator over promoted monitors.

Fits a non-negative sparse linear combination on the selection set only.
Never tunes on locked evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import numpy as np

from .schema import AgentTrajectory, Label
from .synthesis import CandidateMonitor


ScoreFn = Callable[[AgentTrajectory], float]


@dataclass
class SparseAggregator:
    """
    alert_strength = sigmoid(w · x + b) with w >= 0, sparse.

    Stage-1 screen optional: if screen_fn set, low-screen trajs get dampened score.
    """

    names: list[str] = field(default_factory=list)
    weights: np.ndarray | None = None
    bias: float = 0.0
    screen_fn: ScoreFn | None = None
    screen_threshold: float = 0.0
    fitted: bool = False
    provenance: dict[str, Any] = field(default_factory=dict)

    def fit(
        self,
        trajectories: Sequence[AgentTrajectory],
        candidates: list[CandidateMonitor],
        *,
        max_features: int = 8,
        l1: float = 0.05,
        n_iters: int = 400,
        lr: float = 0.15,
        seed: int = 0,
    ) -> "SparseAggregator":
        if not candidates or not trajectories:
            self.names = []
            self.weights = np.array([])
            self.fitted = True
            return self

        X = self._matrix(trajectories, candidates)
        y = np.array([1.0 if t.label == Label.HARMFUL else 0.0 for t in trajectories])
        n, d = X.shape
        rng = np.random.default_rng(seed)

        # Init weights proportional to point-biserial correlation with y
        w = np.zeros(d)
        for j in range(d):
            col = X[:, j]
            if col.std() < 1e-9:
                continue
            w[j] = max(0.0, float(np.corrcoef(col, y)[0, 1])) if y.std() > 1e-9 else 0.0
        if w.sum() < 1e-9:
            w = np.ones(d) / d
        b = 0.0

        # Signed sparse logistic (allow negative weights so "hardens"/"authorized"
        # can suppress score). L1 + soft non-negativity prior on harm-positive names.
        harm_positive = np.array([
            0.0 if any(tok in candidates[j].name for tok in (
                "harden", "authorization_covers", "authorization_present",
                "benign_explanation", "ev_benign",
            )) else 1.0
            for j in range(d)
        ])
        for _ in range(n_iters):
            z = X @ w + b
            p = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
            err = p - y
            grad_w = (X.T @ err) / n + l1 * np.sign(w)
            grad_b = float(err.mean())
            w = w - lr * grad_w
            # Soft project: harm-positive features prefer w>=0
            w = np.where(harm_positive > 0.5, np.maximum(-0.05, w), w)
            b = b - lr * grad_b

        # Sparsify: keep top-k by |weight|
        if d > max_features:
            keep = np.argsort(-np.abs(w))[:max_features]
            mask = np.zeros(d, dtype=bool)
            mask[keep] = True
            w = w * mask
            for _ in range(80):
                z = X @ w + b
                p = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
                err = p - y
                grad_w = (X.T @ err) / n + l1 * np.sign(w)
                grad_b = float(err.mean())
                w = (w - lr * grad_w) * mask
                w = np.where(harm_positive > 0.5, np.maximum(-0.05, w), w)
                b = b - lr * grad_b

        self.names = [c.name for c in candidates]
        self.weights = w
        self.bias = float(b)
        self.fitted = True
        self.provenance = {
            "n_train": n,
            "n_features": int((w > 1e-6).sum()),
            "l1": l1,
            "max_features": max_features,
            "weights": {self.names[i]: float(w[i]) for i in range(d) if w[i] > 1e-6},
            "bias": self.bias,
        }

        # Stage-1 screen: mean of top continuous candidates
        cont = [c for c in candidates if not c.name.startswith("thr_")]
        if cont:
            def screen(t: AgentTrajectory) -> float:
                vals = [c.score(t) for c in cont[:4]]
                return float(np.mean(vals)) if vals else 0.0
            self.screen_fn = screen
            # threshold at ~30th percentile of harmful scores on train
            h_scores = [screen(t) for t in trajectories if t.label == Label.HARMFUL]
            self.screen_threshold = float(np.percentile(h_scores, 20)) if h_scores else 0.0
        return self

    def _matrix(
        self,
        trajectories: Sequence[AgentTrajectory],
        candidates: list[CandidateMonitor],
    ) -> np.ndarray:
        rows = []
        for t in trajectories:
            row = []
            for c in candidates:
                try:
                    v = float(c.score(t))
                except Exception:
                    v = 0.0
                row.append(v)
            rows.append(row)
        X = np.asarray(rows, dtype=float)
        # Robust scale columns
        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0) * 1.4826
        mad = np.where(mad < 1e-8, 1.0, mad)
        return (X - med) / mad

    def score(self, t: AgentTrajectory, candidates: list[CandidateMonitor]) -> float:
        if not self.fitted or self.weights is None or not candidates:
            return 0.0
        # Align by name
        name_to_c = {c.name: c for c in candidates}
        x = []
        for name in self.names:
            c = name_to_c.get(name)
            if c is None:
                x.append(0.0)
            else:
                try:
                    x.append(float(c.score(t)))
                except Exception:
                    x.append(0.0)
        x_arr = np.asarray(x, dtype=float)
        # Same normalization approx: clip extremes
        z = float(x_arr @ self.weights + self.bias)
        p = float(1.0 / (1.0 + np.exp(-np.clip(z, -30, 30))))
        if self.screen_fn is not None:
            s = float(self.screen_fn(t))
            if s < self.screen_threshold * 0.5:
                p *= 0.35  # dampen clearly quiet sessions
        return p

    def decomposition(
        self,
        t: AgentTrajectory,
        candidates: list[CandidateMonitor],
    ) -> dict[str, float]:
        name_to_c = {c.name: c for c in candidates}
        parts: dict[str, float] = {}
        if self.weights is None:
            return parts
        for i, name in enumerate(self.names):
            if self.weights[i] <= 1e-6:
                continue
            c = name_to_c.get(name)
            v = float(c.score(t)) if c else 0.0
            parts[name] = float(self.weights[i] * v)
        parts["bias"] = self.bias
        parts["total"] = self.score(t, candidates)
        return parts

    def to_dict(self) -> dict[str, Any]:
        return {
            "fitted": self.fitted,
            "names": self.names,
            "weights": self.weights.tolist() if self.weights is not None else [],
            "bias": self.bias,
            "screen_threshold": self.screen_threshold,
            "provenance": self.provenance,
        }
