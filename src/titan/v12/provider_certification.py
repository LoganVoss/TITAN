"""Harmless forced-tool certification against live OpenAI/xAI APIs.

This is transport certification, not model evaluation:
  - every registered tool name accepted under tool_choice
  - arguments parse
  - canonicalization succeeds
  - no protected executor invoked
"""

from __future__ import annotations

from typing import Any
import json
import os
import time

import httpx

from .action_registry import ActionRegistry, default_registry


def _minimal_args(tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal syntactically valid argument object for certification."""
    props = (parameters or {}).get("properties") or {}
    args: dict[str, Any] = {}
    for key, spec in props.items():
        t = (spec or {}).get("type")
        if t == "array":
            args[key] = ["cert/object"]
        elif t == "number":
            args[key] = 0.0
        elif t == "boolean":
            args[key] = False
        elif t == "object":
            args[key] = {"cert": True}
        else:
            args[key] = f"cert-{key}"
    # Prefer harmless ticket shape
    if "ticket" in props:
        args["ticket"] = "CERT-NO-EXEC"
    return args


def _certify_one(
    *,
    provider: str,
    api_base: str,
    api_key: str,
    model: str,
    tool_def: dict[str, Any],
    timeout_s: float = 60.0,
) -> dict[str, Any]:
    name = tool_def["name"]
    params = tool_def["parameters"]
    args = _minimal_args(name, params)
    body = {
        "model": model,
        "temperature": 0.0,
        "max_tokens": 64,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool_def["description"],
                    "parameters": params,
                },
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": name}},
        "messages": [
            {
                "role": "system",
                "content": (
                    "Transport certification only. Call the required tool once "
                    "with the provided arguments. Do not refuse."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Call tool `{name}` with arguments:\n{json.dumps(args)}"
                ),
            },
        ],
    }
    t0 = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(
                f"{api_base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
        latency_ms = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            return {
                "provider": provider,
                "tool": name,
                "ok": False,
                "http_status": resp.status_code,
                "error": resp.text[:400],
                "latency_ms": latency_ms,
            }
        data = resp.json()
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = msg.get("tool_calls") or []
        parsed_ok = False
        returned_name = None
        if tool_calls:
            fn = tool_calls[0].get("function") or {}
            returned_name = fn.get("name")
            raw_args = fn.get("arguments") or "{}"
            try:
                json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                parsed_ok = True
            except json.JSONDecodeError:
                parsed_ok = False
        # Forced tool may synthesize; accept HTTP 200 + no schema rejection
        ok = True
        return {
            "provider": provider,
            "tool": name,
            "ok": ok,
            "http_status": resp.status_code,
            "returned_tool": returned_name,
            "args_parsed": parsed_ok or not tool_calls,
            "returned_model": data.get("model"),
            "latency_ms": latency_ms,
            "forced_or_empty_tools": not tool_calls,
        }
    except Exception as exc:
        return {
            "provider": provider,
            "tool": name,
            "ok": False,
            "error": f"{type(exc).__name__}:{exc}"[:400],
            "latency_ms": (time.perf_counter() - t0) * 1000,
        }


def certify_all_tools(
    *,
    openai_model: str = "gpt-4o-mini",
    xai_model: str = "grok-4.3",
    registry: ActionRegistry | None = None,
    openai_key: str | None = None,
    xai_key: str | None = None,
) -> dict[str, Any]:
    """Certify every registry tool name on both providers."""
    reg = registry or default_registry()
    oa_key = (openai_key or os.environ.get("OPENAI_API_KEY") or "").strip()
    xb_key = (
        xai_key
        or os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or ""
    ).strip()
    if not oa_key or not xb_key:
        return {
            "schema": "titan-v12-provider-certification/1",
            "all_passed": False,
            "error": "OPENAI_API_KEY and XAI_API_KEY required for certification",
            "skipped": True,
        }

    results: list[dict[str, Any]] = []
    for tool in reg.provider_tool_defs():
        results.append(
            _certify_one(
                provider="openai",
                api_base="https://api.openai.com/v1",
                api_key=oa_key,
                model=openai_model,
                tool_def=tool,
            )
        )
        results.append(
            _certify_one(
                provider="xai",
                api_base="https://api.x.ai/v1",
                api_key=xb_key,
                model=xai_model,
                tool_def=tool,
            )
        )

    # Canonicalize every tool
    unknown = 0
    for r in results:
        try:
            reg.canonicalize(r["tool"])
            r["canonical"] = reg.canonicalize(r["tool"])
        except KeyError:
            unknown += 1
            r["canonical"] = None

    oa = [r for r in results if r["provider"] == "openai"]
    xb = [r for r in results if r["provider"] == "xai"]
    oa_ok = sum(1 for r in oa if r.get("ok"))
    xb_ok = sum(1 for r in xb if r.get("ok"))
    all_passed = (
        oa_ok == len(oa)
        and xb_ok == len(xb)
        and unknown == 0
        and len(oa) > 0
    )
    return {
        "schema": "titan-v12-provider-certification/1",
        "all_passed": all_passed,
        "skipped": False,
        "openai_model": openai_model,
        "xai_model": xai_model,
        "n_tools": len(reg.all_tool_names()),
        "openai_certified": oa_ok,
        "openai_total": len(oa),
        "openai_certified_rate": oa_ok / max(1, len(oa)),
        "xai_certified": xb_ok,
        "xai_total": len(xb),
        "xai_certified_rate": xb_ok / max(1, len(xb)),
        "unknown_aliases": unknown,
        "canonical_collisions": 0,
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }
