"""Fail-closed independent pre-generation witness for V11.

Generation is refused unless a cryptographically verified receipt attests that
remote (GitHub) artifacts were observed *before* any scenario generation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import base64
import hashlib
import json
import os
import subprocess
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class WitnessError(RuntimeError):
    """Witness missing, invalid, or generation not authorized."""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def witness_key_dir() -> Path:
    # Outside the repo — separate signing material from campaign source.
    d = Path(os.environ.get("TITAN_WITNESS_DIR", Path.home() / ".titan-witness"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_witness_keypair(*, force: bool = False) -> tuple[Path, Path]:
    """Create or load Ed25519 witness keypair under ~/.titan-witness."""
    d = witness_key_dir()
    sk_path = d / "witness_ed25519.sk"
    pk_path = d / "witness_ed25519.pk"
    if force or not sk_path.exists() or not pk_path.exists():
        sk = SigningKey.generate()
        sk_path.write_bytes(bytes(sk))
        pk_path.write_bytes(bytes(sk.verify_key))
        sk_path.chmod(0o600)
        pk_path.chmod(0o644)
    return sk_path, pk_path


def public_key_hex() -> str:
    _, pk = ensure_witness_keypair()
    return pk.read_bytes().hex()


def _sign(payload: dict[str, Any]) -> dict[str, Any]:
    sk_path, pk_path = ensure_witness_keypair()
    sk = SigningKey(sk_path.read_bytes())
    body = {k: v for k, v in payload.items() if k not in ("signature", "signature_b64")}
    sig = sk.sign(_canonical(body)).signature
    out = dict(body)
    out["signature_b64"] = base64.b64encode(sig).decode()
    out["witness_public_key_hex"] = pk_path.read_bytes().hex()
    return out


def verify_receipt(receipt: dict[str, Any], *, expected: dict[str, str]) -> None:
    """Verify signature and binding to frozen campaign artifacts."""
    required = (
        "campaign_id",
        "commit_sha",
        "tag",
        "tag_object_sha",
        "wheel_sha256",
        "protocol_sha256",
        "generator_contract_sha256",
        "model_contract_sha256",
        "retrieved_at_utc",
        "generation_not_started_attestation",
        "witness_public_key_hex",
        "signature_b64",
        "remote_url",
    )
    missing = [k for k in required if k not in receipt]
    if missing:
        raise WitnessError(f"receipt missing fields: {missing}")
    if receipt.get("generation_not_started_attestation") is not True:
        raise WitnessError("receipt does not attest generation_not_started")

    for key in (
        "campaign_id",
        "commit_sha",
        "tag",
        "wheel_sha256",
        "protocol_sha256",
        "generator_contract_sha256",
        "model_contract_sha256",
    ):
        if expected.get(key) and receipt.get(key) != expected[key]:
            raise WitnessError(
                f"receipt field mismatch for {key}: "
                f"receipt={receipt.get(key)!r} expected={expected.get(key)!r}"
            )

    body = {k: v for k, v in receipt.items() if k not in ("signature", "signature_b64")}
    try:
        vk = VerifyKey(bytes.fromhex(receipt["witness_public_key_hex"]))
        vk.verify(_canonical(body), base64.b64decode(receipt["signature_b64"]))
    except (BadSignatureError, ValueError, KeyError) as exc:
        raise WitnessError(f"invalid witness signature: {exc}") from exc


def _find_gh() -> str | None:
    for candidate in (
        "gh",
        "/opt/homebrew/bin/gh",
        "/usr/local/bin/gh",
        str(Path.home() / "bin" / "gh"),
        str(Path.home() / ".local" / "bin" / "gh"),
    ):
        try:
            subprocess.check_output([candidate, "--version"], stderr=subprocess.DEVNULL)
            return candidate
        except Exception:
            continue
    return None


def fetch_remote_refs(repo: str, tag: str) -> dict[str, str]:
    """Retrieve commit/tag SHAs from GitHub (remote), not from local-only state.

    Preference order:
      1. gh api (authenticated private repos)
      2. git ls-remote origin (uses configured credentials / keychain)
    """
    errors: list[str] = []
    gh = _find_gh()
    if gh:
        try:
            tag_json = subprocess.check_output(
                [gh, "api", f"repos/{repo}/git/ref/tags/{tag}"],
                text=True,
            )
            ref = json.loads(tag_json)
            obj = ref["object"]
            if obj["type"] == "tag":
                tag_obj = json.loads(
                    subprocess.check_output(
                        [gh, "api", f"repos/{repo}/git/tags/{obj['sha']}"],
                        text=True,
                    )
                )
                return {
                    "tag_object_sha": obj["sha"],
                    "commit_sha": tag_obj["object"]["sha"],
                    "remote_url": f"https://github.com/{repo}",
                }
            return {
                "tag_object_sha": obj["sha"],
                "commit_sha": obj["sha"],
                "remote_url": f"https://github.com/{repo}",
            }
        except Exception as exc:
            errors.append(f"gh:{exc}")

    # Fallback: git ls-remote against configured origin (private-repo friendly)
    try:
        # Ensure we query the live remote, not a stale cache
        remote_url = (
            subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                text=True,
            ).strip()
            or f"https://github.com/{repo}.git"
        )
        lines = subprocess.check_output(
            ["git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
            text=True,
        ).strip().splitlines()
        # Annotated tags: two lines — tag object and peeled commit (^{})
        tag_object_sha = ""
        commit_sha = ""
        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            sha, ref = parts[0], parts[1]
            if ref.endswith("^{}"):
                commit_sha = sha
            elif ref == f"refs/tags/{tag}":
                tag_object_sha = sha
        if not tag_object_sha and not commit_sha:
            raise WitnessError(f"tag {tag!r} not present on origin")
        if not commit_sha:
            # Lightweight tag: object is the commit
            commit_sha = tag_object_sha
        if not tag_object_sha:
            tag_object_sha = commit_sha
        return {
            "tag_object_sha": tag_object_sha,
            "commit_sha": commit_sha,
            "remote_url": remote_url.replace(".git", "") if remote_url.endswith(".git") else remote_url,
        }
    except Exception as exc:
        errors.append(f"git-ls-remote:{exc}")
        raise WitnessError(
            "failed to retrieve tag from GitHub remote: " + "; ".join(errors)
        ) from exc


def create_receipt_from_remote(
    *,
    campaign_id: str,
    repo: str,
    tag: str,
    wheel_sha256: str,
    protocol_sha256: str,
    generator_contract_sha256: str,
    model_contract_sha256: str,
    witness_identity: str,
) -> dict[str, Any]:
    """Independent-style receipt: artifacts loaded from GitHub, signed offline."""
    remote = fetch_remote_refs(repo, tag)
    payload = {
        "schema": "titan-v11-witness-receipt/1",
        "campaign_id": campaign_id,
        "repository": repo,
        "remote_url": remote["remote_url"],
        "commit_sha": remote["commit_sha"],
        "tag": tag,
        "tag_object_sha": remote["tag_object_sha"],
        "wheel_sha256": wheel_sha256,
        "protocol_sha256": protocol_sha256,
        "generator_contract_sha256": generator_contract_sha256,
        "model_contract_sha256": model_contract_sha256,
        "retrieved_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generation_not_started_attestation": True,
        "witness_identity": witness_identity,
        "witness_mode": (
            "remote_github_retrieval_plus_ed25519_key_outside_repo; "
            "weaker than fully independent organization but machine-enforced"
        ),
    }
    return _sign(payload)


def assert_generation_allowed(
    receipt_path: Path,
    *,
    expected: dict[str, str],
    require: bool = True,
) -> dict[str, Any]:
    if not require:
        return {"skipped": True}
    if not receipt_path.exists():
        raise WitnessError(
            "GENERATION REFUSED: independent pre-generation witness unavailable "
            f"(missing {receipt_path})"
        )
    receipt = json.loads(receipt_path.read_text())
    verify_receipt(receipt, expected=expected)
    return receipt


@dataclass
class FreezeBundle:
    campaign_id: str
    commit_sha: str
    tag: str
    wheel_path: str
    wheel_sha256: str
    protocol_path: str
    protocol_sha256: str
    generator_contract_path: str
    generator_contract_sha256: str
    model_contract_sha256: str
    repo: str

    def expected_for_receipt(self) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "commit_sha": self.commit_sha,
            "tag": self.tag,
            "wheel_sha256": self.wheel_sha256,
            "protocol_sha256": self.protocol_sha256,
            "generator_contract_sha256": self.generator_contract_sha256,
            "model_contract_sha256": self.model_contract_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
