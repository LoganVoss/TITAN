"""V12 witness gate — reuses V11 Ed25519 + remote retrieval machinery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Re-export V11 witness with V12-facing names.
from titan.v11.witness import (  # noqa: F401
    WitnessError,
    assert_generation_allowed,
    create_receipt_from_remote,
    ensure_witness_keypair,
    public_key_hex,
    verify_receipt,
    fetch_remote_refs,
)


def require_receipt(
    receipt_path: Path,
    *,
    expected: dict[str, str],
) -> dict[str, Any]:
    """Fail-closed generation unlock."""
    try:
        return assert_generation_allowed(receipt_path, expected=expected, require=True)
    except WitnessError as exc:
        raise WitnessError(
            "GENERATION REFUSED:\n"
            "independent pre-generation witness unavailable or invalid\n"
            f"{exc}"
        ) from exc
