# TITAN V5 Blocker Specification (Phase 1)

## Protected action classes

| Action | Asset | Irreversible boundary | Evidence required | Latency | False-block tol | FN tol | Fallback |
|---|---|---|---|---|---|---|---|
| `queue_training` | Training pipeline | Train job accepted | Poison/provenance + canary health | p99 < 5s | ≤1% | ≤5% research | HUMAN_CONFIRM |
| `merge_training_data` | Dataset shards | Shard marked training-ready | Cluster/influence/provenance | p99 < 10s | ≤2% | ≤5% | ESCROW |
| `weaken_canary` / `remove_canary` | Eval suite | Canary disabled | Coverage delta | p99 < 2s | ≤1% | ≤2% | BLOCK temp |
| `modify_safeguard` | Monitors/policy | File written | Auth + effect delta | p99 < 3s | ≤1% | ≤2% | ESCROW |
| `export_credential` | Secrets | Egress complete | Path + auth | p99 < 1s | ≤0.5% | ≤1% | BLOCK |
| `disable_monitoring` | Control plane | Monitor off | Kernel only | p99 < 1s | 0% | 0% | BLOCK always |
| `deploy_protected` | Production env | Deploy committed | Auth + tests | p99 < 15s | ≤2% | ≤5% | HUMAN_CONFIRM |

## Decision dispositions

`ALLOW | ALLOW_WITH_LOGGING | REQUEST_EVIDENCE | SHADOW_EXECUTE | ESCROW | HUMAN_CONFIRM | BLOCK`

## Dual-channel autonomous block

Requires **A ∧ B** (or deterministic kernel violation):

- **A behavioral:** trajectory/hazard/authorization mismatch  
- **B effect:** counterfactual regression / probe failure / invariant violation  

## Immutable kernel (TITAN cannot modify)

Protected taxonomy, min authorizations, max autonomous authority, logging, promotion rules, rollback, causal field bans, emergency shutdown, external owners.

## Human override (break-glass)

Named identity, reason, expiration, scoped auth, full audit, post-action review.
