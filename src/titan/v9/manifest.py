"""
SHA-256 artifact sealing and completion receipts for TITAN V9.

A completion receipt can only be issued after every file in the manifest has
been verified.  Receipt verification re-verifies the files, so changing one
byte after completion invalidates the campaign.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


MANIFEST_SCHEMA = "titan-v9-sealed-manifest-1"
RECEIPT_SCHEMA = "titan-v9-completion-receipt-1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestIntegrityError(ValueError):
    """Raised when a manifest or completion receipt is not trustworthy."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_json(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ManifestIntegrityError(f"{path}: non-finite float")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ManifestIntegrityError(f"{path}: keys must be strings")
            result[key] = _normalize_json(item, f"{path}.{key}")
        return dict(sorted(result.items()))
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, f"{path}[]") for item in value]
    raise ManifestIntegrityError(f"{path}: unsupported type {type(value).__name__}")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _normalize_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _content_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_relative_path(relative_path: str) -> str:
    if not isinstance(relative_path, str) or not relative_path:
        raise ManifestIntegrityError("manifest path must be a non-empty string")
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or "." == relative_path:
        raise ManifestIntegrityError(f"unsafe manifest path: {relative_path!r}")
    normalized = path.as_posix()
    if normalized.startswith("../") or normalized == "..":
        raise ManifestIntegrityError(f"unsafe manifest path: {relative_path!r}")
    return normalized


def _resolve_member(root: Path, relative_path: str) -> Path:
    normalized = _validate_relative_path(relative_path)
    root_resolved = root.resolve()
    candidate = root / Path(normalized)
    if candidate.is_symlink():
        raise ManifestIntegrityError(f"symlinks cannot be sealed: {normalized}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ManifestIntegrityError(f"path escapes manifest root: {normalized}") from exc
    return resolved


@dataclass(frozen=True, order=True)
class FileSeal:
    relative_path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relative_path",
            _validate_relative_path(self.relative_path),
        )
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise ManifestIntegrityError("file seal requires a lowercase SHA-256 digest")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
        ):
            raise ManifestIntegrityError("file size must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FileSeal":
        return cls(
            relative_path=str(value.get("path", "")),
            sha256=str(value.get("sha256", "")),
            size_bytes=value.get("size_bytes", -1),
        )


@dataclass(frozen=True)
class ManifestVerification:
    manifest_hash_valid: bool
    missing: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    size_mismatch: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            self.manifest_hash_valid
            and not self.missing
            and not self.changed
            and not self.size_mismatch
            and not self.unexpected
            and not self.errors
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "manifest_hash_valid": self.manifest_hash_valid,
            "missing": list(self.missing),
            "changed": list(self.changed),
            "size_mismatch": list(self.size_mismatch),
            "unexpected": list(self.unexpected),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class SealedManifest:
    entries: tuple[FileSeal, ...]
    created_at: str
    metadata: Mapping[str, Any]
    declared_hash: str
    schema: str = MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != MANIFEST_SCHEMA:
            raise ManifestIntegrityError(f"unsupported manifest schema {self.schema!r}")
        if not isinstance(self.created_at, str) or not self.created_at.strip():
            raise ManifestIntegrityError("created_at is required")
        entries = tuple(sorted(self.entries))
        paths = [entry.relative_path for entry in entries]
        if len(paths) != len(set(paths)):
            raise ManifestIntegrityError("manifest contains duplicate paths")
        metadata = _normalize_json(self.metadata)
        content = self._content(entries=entries, metadata=metadata)
        expected = _content_hash(content)
        if self.declared_hash != expected:
            raise ManifestIntegrityError(
                f"manifest hash mismatch: declared={self.declared_hash} actual={expected}"
            )
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "metadata", _freeze_json(metadata))

    def _content(
        self,
        *,
        entries: Sequence[FileSeal] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        selected_entries = self.entries if entries is None else entries
        selected_metadata = self.metadata if metadata is None else metadata
        return {
            "schema": self.schema,
            "algorithm": "sha256",
            "created_at": self.created_at,
            "metadata": _thaw_json(selected_metadata),
            "entries": [entry.to_dict() for entry in selected_entries],
        }

    @classmethod
    def create(
        cls,
        root: str | Path,
        paths: Iterable[str | Path],
        *,
        created_at: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> "SealedManifest":
        root_path = Path(root).resolve()
        if not root_path.is_dir():
            raise ManifestIntegrityError(f"manifest root is not a directory: {root_path}")
        entries: list[FileSeal] = []
        seen: set[str] = set()
        for supplied in paths:
            supplied_path = Path(supplied)
            if supplied_path.is_absolute():
                try:
                    relative = supplied_path.resolve().relative_to(root_path).as_posix()
                except ValueError as exc:
                    raise ManifestIntegrityError(
                        f"path is outside manifest root: {supplied_path}"
                    ) from exc
            else:
                relative = PurePosixPath(supplied_path.as_posix()).as_posix()
            relative = _validate_relative_path(relative)
            if relative in seen:
                raise ManifestIntegrityError(f"duplicate manifest path: {relative}")
            seen.add(relative)
            resolved = _resolve_member(root_path, relative)
            if not resolved.is_file():
                raise ManifestIntegrityError(f"artifact is missing or not a file: {relative}")
            entries.append(
                FileSeal(
                    relative_path=relative,
                    sha256=_sha256_file(resolved),
                    size_bytes=resolved.stat().st_size,
                )
            )
        if not entries:
            raise ManifestIntegrityError("cannot seal an empty artifact set")
        clean_metadata = _normalize_json(metadata or {})
        provisional = {
            "schema": MANIFEST_SCHEMA,
            "algorithm": "sha256",
            "created_at": created_at,
            "metadata": clean_metadata,
            "entries": [entry.to_dict() for entry in sorted(entries)],
        }
        return cls(
            entries=tuple(entries),
            created_at=created_at,
            metadata=clean_metadata,
            declared_hash=_content_hash(provisional),
        )

    @classmethod
    def from_dict(cls, artifact: Mapping[str, Any]) -> "SealedManifest":
        content = artifact.get("content", {})
        if not isinstance(content, Mapping):
            raise ManifestIntegrityError("manifest content must be an object")
        if content.get("schema") != artifact.get("schema"):
            raise ManifestIntegrityError("manifest schema fields do not match")
        if content.get("algorithm") != "sha256":
            raise ManifestIntegrityError("manifest algorithm must be sha256")
        entries = tuple(
            FileSeal.from_dict(item) for item in content.get("entries", [])
        )
        return cls(
            schema=str(artifact.get("schema", "")),
            entries=entries,
            created_at=str(content.get("created_at", "")),
            metadata=content.get("metadata", {}),
            declared_hash=str(artifact.get("declared_hash", "")),
        )

    @property
    def content_hash(self) -> str:
        return self.declared_hash

    def verify(
        self,
        root: str | Path,
        *,
        exact_scope: Iterable[str | Path] | None = None,
    ) -> ManifestVerification:
        root_path = Path(root).resolve()
        missing: list[str] = []
        changed: list[str] = []
        size_mismatch: list[str] = []
        errors: list[str] = []
        for entry in self.entries:
            try:
                candidate = _resolve_member(root_path, entry.relative_path)
                if not candidate.is_file():
                    missing.append(entry.relative_path)
                    continue
                if candidate.stat().st_size != entry.size_bytes:
                    size_mismatch.append(entry.relative_path)
                if _sha256_file(candidate) != entry.sha256:
                    changed.append(entry.relative_path)
            except (OSError, ManifestIntegrityError) as exc:
                errors.append(f"{entry.relative_path}: {exc}")

        unexpected: list[str] = []
        if exact_scope is not None:
            expected = {entry.relative_path for entry in self.entries}
            observed: set[str] = set()
            for supplied in exact_scope:
                path = Path(supplied)
                if path.is_absolute():
                    try:
                        rel = path.resolve().relative_to(root_path).as_posix()
                    except ValueError:
                        errors.append(f"scope path outside root: {path}")
                        continue
                else:
                    rel = PurePosixPath(path.as_posix()).as_posix()
                try:
                    observed.add(_validate_relative_path(rel))
                except ManifestIntegrityError as exc:
                    errors.append(str(exc))
            unexpected.extend(sorted(observed - expected))
            missing.extend(sorted(expected - observed))

        actual_manifest_hash = _content_hash(self._content())
        return ManifestVerification(
            manifest_hash_valid=actual_manifest_hash == self.declared_hash,
            missing=tuple(sorted(set(missing))),
            changed=tuple(sorted(set(changed))),
            size_mismatch=tuple(sorted(set(size_mismatch))),
            unexpected=tuple(sorted(set(unexpected))),
            errors=tuple(sorted(set(errors))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "declared_hash": self.declared_hash,
            "content": self._content(),
        }


@dataclass(frozen=True)
class ReceiptVerification:
    receipt_hash_valid: bool
    bindings_valid: bool
    manifest: ManifestVerification
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            self.receipt_hash_valid
            and self.bindings_valid
            and self.manifest.ok
            and not self.errors
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "receipt_hash_valid": self.receipt_hash_valid,
            "bindings_valid": self.bindings_valid,
            "manifest": self.manifest.to_dict(),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class CompletionReceipt:
    content: Mapping[str, Any]
    declared_hash: str
    schema: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RECEIPT_SCHEMA:
            raise ManifestIntegrityError(f"unsupported receipt schema {self.schema!r}")
        content = _normalize_json(self.content)
        required = {
            "campaign_id",
            "status",
            "completed_at",
            "protocol_sha256",
            "manifest_sha256",
            "artifact_count",
        }
        missing = sorted(required - set(content))
        if missing:
            raise ManifestIntegrityError(f"missing receipt fields: {missing}")
        if content["status"] != "complete":
            raise ManifestIntegrityError("completion receipt status must be 'complete'")
        for key in ("campaign_id", "completed_at"):
            if not isinstance(content[key], str) or not content[key].strip():
                raise ManifestIntegrityError(f"{key} is required")
        for key in ("protocol_sha256", "manifest_sha256"):
            if not isinstance(content[key], str) or not _SHA256_RE.fullmatch(content[key]):
                raise ManifestIntegrityError(f"{key} must be a SHA-256 digest")
        count = content["artifact_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ManifestIntegrityError("artifact_count must be a positive integer")
        expected = _content_hash(content)
        if self.declared_hash != expected:
            raise ManifestIntegrityError(
                f"receipt hash mismatch: declared={self.declared_hash} actual={expected}"
            )
        object.__setattr__(self, "content", _freeze_json(content))

    @classmethod
    def issue(
        cls,
        *,
        campaign_id: str,
        protocol_sha256: str,
        manifest: SealedManifest,
        root: str | Path,
        completed_at: str,
    ) -> "CompletionReceipt":
        verification = manifest.verify(root)
        if not verification.ok:
            raise ManifestIntegrityError(
                f"cannot issue completion receipt: {verification.to_dict()}"
            )
        content = {
            "campaign_id": campaign_id,
            "status": "complete",
            "completed_at": completed_at,
            "protocol_sha256": protocol_sha256,
            "manifest_sha256": manifest.declared_hash,
            "artifact_count": len(manifest.entries),
        }
        return cls(content=content, declared_hash=_content_hash(content))

    @classmethod
    def from_dict(cls, artifact: Mapping[str, Any]) -> "CompletionReceipt":
        return cls(
            schema=str(artifact.get("schema", "")),
            content=artifact.get("content", {}),
            declared_hash=str(artifact.get("declared_hash", "")),
        )

    def to_content_dict(self) -> dict[str, Any]:
        return _thaw_json(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "declared_hash": self.declared_hash,
            "content": self.to_content_dict(),
        }

    def verify(
        self,
        *,
        protocol_sha256: str,
        manifest: SealedManifest,
        root: str | Path,
    ) -> ReceiptVerification:
        content = self.to_content_dict()
        receipt_hash_valid = _content_hash(content) == self.declared_hash
        errors: list[str] = []
        bindings_valid = True
        if content.get("protocol_sha256") != protocol_sha256:
            bindings_valid = False
            errors.append("protocol hash does not match receipt")
        if content.get("manifest_sha256") != manifest.declared_hash:
            bindings_valid = False
            errors.append("manifest hash does not match receipt")
        if content.get("artifact_count") != len(manifest.entries):
            bindings_valid = False
            errors.append("artifact count does not match manifest")
        manifest_verification = manifest.verify(root)
        return ReceiptVerification(
            receipt_hash_valid=receipt_hash_valid,
            bindings_valid=bindings_valid,
            manifest=manifest_verification,
            errors=tuple(errors),
        )


def seal_manifest(
    root: str | Path,
    paths: Iterable[str | Path],
    *,
    created_at: str,
    metadata: Mapping[str, Any] | None = None,
) -> SealedManifest:
    return SealedManifest.create(
        root,
        paths,
        created_at=created_at,
        metadata=metadata,
    )


def verify_completion_receipt(
    receipt: CompletionReceipt,
    *,
    protocol_sha256: str,
    manifest: SealedManifest,
    root: str | Path,
) -> ReceiptVerification:
    return receipt.verify(
        protocol_sha256=protocol_sha256,
        manifest=manifest,
        root=root,
    )
