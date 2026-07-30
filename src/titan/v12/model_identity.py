"""Resolve and freeze exact provider model identities (not moving aliases)."""

from __future__ import annotations

from typing import Any
import json
import os


def _require_httpx():
    """Lazy import so offline unit tests do not need the live HTTP stack."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "httpx is required for live model-identity calls. "
            "Install with: pip install 'titan-safety[live]' or pip install httpx"
        ) from exc
    return httpx


def list_openai_model_ids(api_key: str | None = None) -> list[str]:
    key = (api_key or os.environ.get("OPENAI_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("OPENAI_API_KEY required")
    httpx = _require_httpx()
    with httpx.Client(timeout=60.0) as client:
        resp = client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
    resp.raise_for_status()
    return sorted(m["id"] for m in resp.json().get("data", []))


def list_xai_language_models(api_key: str | None = None) -> list[dict[str, Any]]:
    key = (
        api_key
        or os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or ""
    ).strip()
    if not key:
        raise RuntimeError("XAI_API_KEY required")
    httpx = _require_httpx()
    with httpx.Client(timeout=60.0) as client:
        resp = client.get(
            "https://api.x.ai/v1/language-models",
            headers={"Authorization": f"Bearer {key}"},
        )
        if resp.status_code >= 400:
            # fallback
            resp = client.get(
                "https://api.x.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return [{"id": m["id"] if isinstance(m, dict) else m} for m in data]
        return list(resp.json().get("models") or [])


def resolve_openai_snapshot(
    requested: str,
    *,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Probe chat completions once; return exact returned model id."""
    key = (api_key or os.environ.get("OPENAI_API_KEY") or "").strip()
    available = set(list_openai_model_ids(key))
    body: dict[str, Any] = {
        "model": requested,
        "messages": [{"role": "user", "content": "model identity probe"}],
    }
    # GPT-5 family requires max_completion_tokens; older models use max_tokens
    if requested.lower().startswith(("gpt-5", "o1", "o3")):
        body["max_completion_tokens"] = 16
    else:
        body["max_tokens"] = 4
        body["temperature"] = 0
    httpx = _require_httpx()
    with httpx.Client(timeout=90.0) as client:
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json=body,
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"OpenAI resolve failed for {requested}: {resp.text[:300]}")
    data = resp.json()
    returned = str(data.get("model") or requested)
    if returned not in available and requested not in available:
        # still accept returned if API used it
        pass
    if returned not in available and returned != requested:
        # soft: returned snapshot should exist
        if not any(returned.startswith(a) or a.startswith(returned) for a in available):
            raise RuntimeError(
                f"returned OpenAI model {returned!r} not listed in /v1/models"
            )
    return {
        "provider": "openai",
        "requested_alias": requested,
        "frozen_model_id": returned,
        "listed_in_models_api": returned in available,
        "system_fingerprint": data.get("system_fingerprint"),
        "probe_response_id": data.get("id"),
        "lane_role": "higher_capability_transfer",
    }


def resolve_xai_identity(
    requested: str,
    *,
    api_key: str | None = None,
) -> dict[str, Any]:
    key = (
        api_key
        or os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or ""
    ).strip()
    catalog = list_xai_language_models(key)
    by_id = {m.get("id"): m for m in catalog if isinstance(m, dict)}
    # match aliases
    meta = by_id.get(requested)
    if meta is None:
        for m in catalog:
            aliases = m.get("aliases") or []
            if requested in aliases or m.get("id") == requested:
                meta = m
                break
    httpx = _require_httpx()
    with httpx.Client(timeout=90.0) as client:
        resp = client.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": requested,
                "messages": [{"role": "user", "content": "model identity probe"}],
                "max_tokens": 4,
                "temperature": 0,
            },
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"xAI resolve failed for {requested}: {resp.text[:300]}")
    data = resp.json()
    returned = str(data.get("model") or requested)
    fp = data.get("system_fingerprint") or (meta or {}).get("fingerprint")
    return {
        "provider": "xai",
        "requested_alias": requested,
        "frozen_model_id": returned,
        "system_fingerprint": fp,
        "catalog_fingerprint": (meta or {}).get("fingerprint"),
        "version": (meta or {}).get("version"),
        "aliases": (meta or {}).get("aliases") or [],
        "probe_response_id": data.get("id"),
        "lane_role": "reproduction_and_transfer_control",
    }


def build_model_contract(
    *,
    openai_transfer_alias: str = "gpt-5.5",
    openai_reproduction_alias: str = "gpt-4o-mini",
    xai_alias: str = "grok-4.3",
) -> dict[str, Any]:
    """Resolve all identities and produce a sealable model contract."""
    oa_transfer = resolve_openai_snapshot(openai_transfer_alias)
    oa_repro = resolve_openai_snapshot(openai_reproduction_alias)
    xai = resolve_xai_identity(xai_alias)
    contract = {
        "schema": "titan-v12-model-contract/1",
        "naming": {
            "transfer_lane": "frontier_class_transfer_gpt55_vs_grok43",
            "not_claimed": "universal_all_frontier_configs",
            "note": (
                "Primary live lane freezes exact OpenAI GPT-5.5-family snapshot "
                "against exact xAI Grok 4.3 id/fingerprint. Reproduction mini "
                "slice is separate and never pooled into transfer metrics."
            ),
        },
        "primary_live": {
            "provider-openai": {
                "requested_alias": oa_transfer["requested_alias"],
                "frozen_model_id": oa_transfer["frozen_model_id"],
                "system_fingerprint": oa_transfer.get("system_fingerprint"),
            },
            "provider-xai": {
                "requested_alias": xai["requested_alias"],
                "frozen_model_id": xai["frozen_model_id"],
                "system_fingerprint": xai.get("system_fingerprint"),
                "catalog_fingerprint": xai.get("catalog_fingerprint"),
                "version": xai.get("version"),
            },
        },
        "reproduction": {
            "provider-openai": {
                "requested_alias": oa_repro["requested_alias"],
                "frozen_model_id": oa_repro["frozen_model_id"],
            },
            "provider-xai": {
                "requested_alias": xai["requested_alias"],
                "frozen_model_id": xai["frozen_model_id"],
                "system_fingerprint": xai.get("system_fingerprint"),
            },
        },
        "resolution_probes": {
            "openai_transfer": oa_transfer,
            "openai_reproduction": oa_repro,
            "xai": xai,
        },
        "enforcement": {
            "use_frozen_ids_only_after_seal": True,
            "stop_on_returned_model_mismatch": True,
            "stop_on_xai_fingerprint_mismatch": True,
        },
    }
    return contract


def assert_identity_matches_contract(
    *,
    provider: str,
    returned_model: str,
    system_fingerprint: str | None,
    contract: dict[str, Any],
) -> None:
    primary = contract["primary_live"]
    if provider in ("openai", "provider-openai"):
        expected = primary["provider-openai"]["frozen_model_id"]
        if returned_model != expected:
            raise RuntimeError(
                f"MODEL IDENTITY CHANGE: OpenAI returned {returned_model!r}, "
                f"contract requires {expected!r} — campaign stop"
            )
    elif provider in ("xai", "provider-xai"):
        expected = primary["provider-xai"]["frozen_model_id"]
        exp_fp = primary["provider-xai"].get("system_fingerprint")
        if returned_model != expected:
            raise RuntimeError(
                f"MODEL IDENTITY CHANGE: xAI returned {returned_model!r}, "
                f"contract requires {expected!r} — campaign stop"
            )
        if exp_fp and system_fingerprint and system_fingerprint != exp_fp:
            raise RuntimeError(
                f"MODEL FINGERPRINT CHANGE: xAI fp {system_fingerprint!r}, "
                f"contract requires {exp_fp!r} — campaign stop"
            )
