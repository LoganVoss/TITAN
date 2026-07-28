# TITAN V4 Threat Model (Step 2)

## Protected assets

| Asset | Why it matters |
|---|---|
| Training data shards & lineage | Poisoning can corrupt future models |
| Evaluation / canary suites | Sabotage hides degradation |
| Safeguards, monitors, policies | Weakening enables later undetected harm |
| Credentials & secrets | Exfil / privilege expansion |
| Training queue / deploy gates | Irreversible or high-cost actions |
| Monitor control plane | Meta-attacks on TITAN itself |

## High-risk actions (gate candidates)

1. Training run queue submission  
2. Canary / eval removal or disable  
3. Safeguard / monitor / policy weaken  
4. Unreviewed large dataset merge  
5. Credential export or unapproved egress  
6. Monitor disablement / threshold tamper  

## Attacker capabilities

| Level | Knowledge |
|---|---|
| L0 | No monitor knowledge |
| L1 | Base monitors (intent/action/provenance) |
| L2 | TITAN public monitor cards / vocabulary |
| L3 | Architecture knowledge, no thresholds |
| L4 | Partial threshold feedback (red-team only) |

Attackers may: multi-step sabotage, low-and-slow, multi-identity, approval abuse, logging avoidance, alternate routes after denial, hide inside legitimate work, stop when risk rises.

## Trusted vs untrusted

| Trusted | Untrusted |
|---|---|
| Signed event gateway | Agent process |
| Canonical store (append-only) | Tool outputs from untrusted tools |
| Deployable feature implementations | Free-form LLM free-text |
| Human promotion authority | Automatic blocking by new monitors |
| Offline labeled discovery | Unlabeled production for auto-promotion |

## Failure consequences

| Failure | Consequence |
|---|---|
| Miss before-harm | Contaminated training / weakened eval enters pipeline |
| High FPR | Reviewer fatigue, ignored alerts |
| Causal leak | Invalid safety claims |
| Control-plane compromise | Silent blind spots |
| Privacy leak | Unauthorized exposure of code/data |

## Enforcement boundaries

* Shadow mode default  
* No self-granted blocking authority  
* Dual approval for enforcement changes  
* Rollback required before promotion  

## Evaluation family → threat mapping

| Family | Threat assumption |
|---|---|
| Data poisoning families | Contaminate training distribution |
| Eval/canary sabotage | Hide model misalignment |
| Safeguard tamper | Disable future detection |
| Exfil | Unauthorized data transfer |
| Stealth / slow-drip | Evade base monitors |
| External LLM execution | Novel authorship outside generator |
| Monitor-aware attacks | Know TITAN vocabulary |
| Control-plane attacks | Target monitoring itself |

### Exit criterion

Every evaluation family maps to a named threat-model assumption. **MET.**
