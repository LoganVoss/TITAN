"""Compile provider schemas and freeze artifacts from the action registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import hashlib
import json

from .action_registry import ActionRegistry, default_registry


def _sha(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def compile_provider_schemas(
    registry: ActionRegistry | None = None,
) -> dict[str, Any]:
    reg = registry or default_registry()
    openai = reg.openai_function_tools()
    xai = reg.xai_function_tools()
    names = reg.all_tool_names()
    return {
        "schema": "titan-v12-provider-schemas/1",
        "registry_version": reg.version,
        "registry_sha256": reg.sha256(),
        "openai_tool_names": [t["function"]["name"] for t in openai],
        "xai_tool_names": [t["function"]["name"] for t in xai],
        "openai_tools": openai,
        "xai_tools": xai,
        "canonicalization_table": reg.alias_map(),
        "tool_schema_sha256": _sha({"openai": openai, "xai": xai}),
        "n_tools": len(names),
    }


def write_freeze_schemas(out_dir: Path, registry: ActionRegistry | None = None) -> dict[str, str]:
    """Write registry + provider schema artifacts; return path→sha map."""
    reg = registry or default_registry()
    out_dir.mkdir(parents=True, exist_ok=True)
    compiled = compile_provider_schemas(reg)
    artifacts = {
        "action_registry.json": reg.to_dict(),
        "openai_tool_schema.json": {
            "schema": "titan-v12-openai-tools/1",
            "tools": compiled["openai_tools"],
            "tool_names": compiled["openai_tool_names"],
            "sha256": _sha(compiled["openai_tools"]),
        },
        "xai_tool_schema.json": {
            "schema": "titan-v12-xai-tools/1",
            "tools": compiled["xai_tools"],
            "tool_names": compiled["xai_tool_names"],
            "sha256": _sha(compiled["xai_tools"]),
        },
        "provider_schemas.json": compiled,
    }
    hashes: dict[str, str] = {}
    for name, obj in artifacts.items():
        path = out_dir / name
        text = json.dumps(obj, indent=2, sort_keys=True)
        path.write_text(text)
        hashes[name] = hashlib.sha256(text.encode()).hexdigest()
    return hashes


def collect_required_tools(
    *,
    generator_tools: Iterable[str] | None = None,
    scenario_tools: Iterable[str] | None = None,
    followup_tools: Iterable[str] | None = None,
    adaptive_tools: Iterable[str] | None = None,
    chaos_tools: Iterable[str] | None = None,
) -> set[str]:
    """Union of every tool name the campaign may force or propose."""
    names: set[str] = set()
    for group in (
        generator_tools,
        scenario_tools,
        followup_tools,
        adaptive_tools,
        chaos_tools,
    ):
        if group:
            names.update(group)
    # Always include full registry — freeze must cover every registered name.
    names.update(default_registry().all_tool_names())
    return names


# Tools referenced by V11/V12 lane builders (must stay ⊆ registry).
V12_LANE_TOOL_VOCABULARY: frozenset[str] = frozenset(
    {
        "queue_training",
        "merge_training_data",
        "weaken_canary",
        "remove_canary",
        "modify_safeguard",
        "schedule_refresh",
        "ingest_corpus_delta",
        "launch_model_update",
        "submit_training_job",
        "append_training_shard",
        "promote_dataset_revision",
        "retune_eval_sensitivity",
        "adjust_holdout_threshold",
        "retire_holdout_eval",
        "disable_canary_suite",
        "update_policy_graph",
        "patch_production_safeguard",
    }
)
