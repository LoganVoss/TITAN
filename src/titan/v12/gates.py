"""Fail-closed freeze and launch gates for V12 transport completeness."""

from __future__ import annotations

from typing import Any, Iterable
import json

from .action_registry import ActionRegistry, default_registry
from .schema_compiler import V12_LANE_TOOL_VOCABULARY, collect_required_tools, compile_provider_schemas


class FreezeGateError(RuntimeError):
    """Campaign freeze refused — transport or integrity preconditions unmet."""


def freeze_gate_report(
    *,
    registry: ActionRegistry | None = None,
    extra_required_tools: Iterable[str] | None = None,
    certification: dict[str, Any] | None = None,
    require_provider_cert: bool = False,
) -> dict[str, Any]:
    """Compute transport closure status without raising."""
    reg = registry or default_registry()
    compiled = compile_provider_schemas(reg)
    required = collect_required_tools(
        generator_tools=V12_LANE_TOOL_VOCABULARY,
        scenario_tools=extra_required_tools,
        followup_tools=V12_LANE_TOOL_VOCABULARY,
        adaptive_tools=V12_LANE_TOOL_VOCABULARY,
        chaos_tools=V12_LANE_TOOL_VOCABULARY,
    )
    openai_names = set(compiled["openai_tool_names"])
    xai_names = set(compiled["xai_tool_names"])
    alias_map = reg.alias_map()

    missing_registry = sorted(n for n in required if n not in alias_map)
    missing_openai = sorted(n for n in required if n not in openai_names)
    missing_xai = sorted(n for n in required if n not in xai_names)

    # Provider tools must all canonicalize uniquely (already enforced by registry).
    unmapped_provider = sorted(
        n for n in openai_names | xai_names if n not in alias_map
    )

    cert_ok = True
    cert_detail: dict[str, Any] = {"skipped": certification is None}
    if certification is not None:
        cert_ok = bool(certification.get("all_passed"))
        cert_detail = {
            "skipped": False,
            "all_passed": cert_ok,
            "openai_rate": certification.get("openai_certified_rate"),
            "xai_rate": certification.get("xai_certified_rate"),
            "unknown_aliases": certification.get("unknown_aliases", 0),
            "canonical_collisions": certification.get("canonical_collisions", 0),
        }
    elif require_provider_cert:
        cert_ok = False
        cert_detail = {
            "skipped": False,
            "all_passed": False,
            "error": "provider certification required but missing",
        }

    passed = (
        not missing_registry
        and not missing_openai
        and not missing_xai
        and not unmapped_provider
        and cert_ok
    )

    return {
        "schema": "titan-v12-freeze-gate/1",
        "passed": passed,
        "required_tools": sorted(required),
        "n_required": len(required),
        "registry_sha256": reg.sha256(),
        "tool_schema_sha256": compiled["tool_schema_sha256"],
        "missing_registry_mappings": missing_registry,
        "missing_openai_tools": missing_openai,
        "missing_xai_tools": missing_xai,
        "unmapped_provider_tools": unmapped_provider,
        "provider_certification": cert_detail,
        "invariants": {
            "lane_vocab_subseteq_registry": not missing_registry,
            "openai_covers_required": not missing_openai,
            "xai_covers_required": not missing_xai,
            "every_provider_tool_canonicalizes": not unmapped_provider,
            "provider_cert_ok": cert_ok,
        },
    }


def assert_transport_closure(
    *,
    registry: ActionRegistry | None = None,
    extra_required_tools: Iterable[str] | None = None,
    certification: dict[str, Any] | None = None,
    require_provider_cert: bool = False,
) -> dict[str, Any]:
    """Raise FreezeGateError with human-readable FREEZE REFUSED message."""
    report = freeze_gate_report(
        registry=registry,
        extra_required_tools=extra_required_tools,
        certification=certification,
        require_provider_cert=require_provider_cert,
    )
    if report["passed"]:
        return report

    lines = ["FREEZE REFUSED", ""]
    if report["missing_openai_tools"]:
        lines.append("Missing OpenAI tool definitions:")
        for t in report["missing_openai_tools"]:
            lines.append(f"  {t}")
        lines.append("")
    if report["missing_xai_tools"]:
        lines.append("Missing xAI tool definitions:")
        for t in report["missing_xai_tools"]:
            lines.append(f"  {t}")
        lines.append("")
    if report["missing_registry_mappings"]:
        lines.append("Missing canonical mappings:")
        for t in report["missing_registry_mappings"]:
            lines.append(f"  {t} → ?")
        lines.append("")
    if report["unmapped_provider_tools"]:
        lines.append("Provider tools without canonical effect:")
        for t in report["unmapped_provider_tools"]:
            lines.append(f"  {t}")
        lines.append("")
    cert = report["provider_certification"]
    if not cert.get("skipped") and not cert.get("all_passed"):
        lines.append("Provider certification incomplete or failed:")
        lines.append(f"  {json.dumps(cert, sort_keys=True)}")
        lines.append("")
    lines.append(
        "Transport is part of the safety system. "
        "Register every semantic alias before freeze."
    )
    raise FreezeGateError("\n".join(lines))
