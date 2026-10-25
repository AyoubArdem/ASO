"""SecretGuard policy, envelope-encrypted vault, and mandatory broker gateway."""

from __future__ import annotations

import base64
import importlib
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable

from .config import (
    Decision,
    SecretAccessRequest,
    SecretDefinition,
    SecretGuard as SecretGuardDecision,
    SecretMaterial,
    SecretPermissions,
    SecretStatus,
    SecretType,
)
from .db import SecretRepository


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _aesgcm():
    try:
        return importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").AESGCM
    except ImportError as error:
        raise RuntimeError("install cryptography to use SecretVault") from error


class KeyManager(ABC):
    """KEK abstraction. Production implementations should delegate to KMS/HSM."""

    @abstractmethod
    def generate_dek(self) -> bytes: ...

    @abstractmethod
    def wrap_dek(self, dek: bytes, aad: bytes) -> tuple[bytes, bytes, bytes, str, str]: ...

    @abstractmethod
    def unwrap_dek(self, wrapped: bytes, tag: bytes, nonce: bytes, aad: bytes, key_version: str) -> bytes: ...

    @abstractmethod
    def get_current_key_version(self) -> str: ...


class LocalDevelopmentKeyManager(KeyManager):
    """Development-only local KEK provider. Never use as production KMS."""

    development_only = True

    def __init__(self, kek: bytes | None = None, key_id: str = "local-dev-kek", key_version: str = "1") -> None:
        if kek is None:
            encoded = os.environ.get("SECRETGUARD_DEV_KEK_B64")
            if not encoded:
                raise RuntimeError("set SECRETGUARD_DEV_KEK_B64 or inject a KMS-backed KeyManager")
            try:
                kek = base64.urlsafe_b64decode(encoded.encode())
            except Exception as error:
                raise ValueError("SECRETGUARD_DEV_KEK_B64 is invalid") from error
        if len(kek) != 32:
            raise ValueError("AES-256 KEK must be exactly 32 bytes")
        self._kek = bytes(kek)
        self.key_id = key_id
        self.key_version = key_version

    def generate_dek(self) -> bytes:
        return os.urandom(32)

    def wrap_dek(self, dek: bytes, aad: bytes) -> tuple[bytes, bytes, bytes, str, str]:
        nonce = os.urandom(12)
        sealed = _aesgcm()(self._kek).encrypt(nonce, dek, aad)
        return sealed[:-16], sealed[-16:], nonce, self.key_id, self.key_version

    def unwrap_dek(self, wrapped: bytes, tag: bytes, nonce: bytes, aad: bytes, key_version: str) -> bytes:
        if key_version != self.key_version:
            raise ValueError("unknown development KEK version")
        return _aesgcm()(self._kek).decrypt(nonce, wrapped + tag, aad)

    def get_current_key_version(self) -> str:
        return self.key_version


class SecretGuard:
    """Deny-by-default policy evaluator; independent from secret storage."""

    def evaluate_store(self, definition: SecretDefinition, permissions: SecretPermissions) -> SecretGuardDecision:
        reasons: list[str] = []
        if not definition.allowed or not permissions.allowed_use:
            reasons.append("secret_use_not_allowed")
        if permissions.allowed_type and definition.secret_type not in permissions.allowed_type:
            reasons.append("secret_type_not_allowed")
        if "store" not in permissions.allowed_operations or "store" not in definition.operations:
            reasons.append("store_operation_not_allowed")
        if "vault" not in permissions.allowed_destination:
            reasons.append("vault_destination_not_allowed")
        decision = Decision.ALLOW if not reasons else Decision.DENY
        return SecretGuardDecision(definition.secret_id, decision, _utcnow(), tuple(reasons))

    def evaluate_access(self, definition: SecretDefinition | None, permissions: SecretPermissions,
                        request: SecretAccessRequest, status: str | None) -> SecretGuardDecision:
        if definition is None:
            decision = Decision.QUARANTINE if permissions.unregistered else Decision.DENY
            return SecretGuardDecision(request.secret_id, decision, _utcnow(), ("secret_unregistered",))
        reasons: list[str] = []
        if status != SecretStatus.ACTIVE.value:
            reasons.append("secret_not_active")
        if not definition.allowed or not permissions.allowed_use:
            reasons.append("secret_use_not_allowed")
        if permissions.allowed_type and definition.secret_type not in permissions.allowed_type:
            reasons.append("secret_type_not_allowed")
        if request.operation.lower() not in permissions.allowed_operations:
            reasons.append("operation_not_allowed")
        if request.operation.lower() not in definition.operations:
            reasons.append("operation_not_defined")
        if request.destination.lower() not in permissions.allowed_destination:
            reasons.append("destination_not_allowed")
        if request.destination.lower() not in definition.destinations:
            reasons.append("destination_not_defined")
        if not permissions.allowed_exposed or not definition.exposed:
            reasons.append("plaintext_exposure_not_allowed")
        if not request.purpose.strip():
            reasons.append("purpose_required")
        decision = Decision.ALLOW if not reasons else Decision.DENY
        return SecretGuardDecision(request.secret_id, decision, _utcnow(), tuple(reasons))


class SecretVault:
    """Stores ciphertext and performs bounded cryptographic use; no public retrieve."""

    def __init__(self, repository: SecretRepository, key_manager: KeyManager) -> None:
        self._repository = repository
        self._key_manager = key_manager

    @staticmethod
    def _aad(secret_id: str, tenant_id: str, secret_type: str, version: int) -> bytes:
        return f"{secret_id}\0{tenant_id}\0{secret_type}\0{version}".encode()

    def store(self, secret_id: str, tenant_id: str, secret_type: SecretType,
              material: SecretMaterial) -> int:
        try:
            metadata = self._repository.get_secret(secret_id, tenant_id)
            if metadata is None or metadata["status"] != SecretStatus.ACTIVE.value:
                raise PermissionError("secret metadata unavailable")
            version = int(metadata["current_version"]) + 1
            aad = self._aad(secret_id, tenant_id, secret_type.value, version)
            dek = self._key_manager.generate_dek()
            nonce = os.urandom(12)
            sealed = _aesgcm()(dek).encrypt(nonce, bytes(material.value), aad)
            wrapped_dek, dek_tag, dek_nonce, key_id, key_version = self._key_manager.wrap_dek(dek, aad)
            tag = sealed[-16:]
            encrypted = {
                "ciphertext": sealed[:-16], "nonce": nonce, "auth_tag": tag,
                "encrypted_dek": wrapped_dek, "dek_nonce": dek_nonce,
                "dek_auth_tag": dek_tag, "kek_key_id": key_id, "kek_version": key_version,
            }
            self._repository.save_version(secret_id, version, encrypted)
            return version
        finally:
            material.clear()

    def _resolve_version(self, secret_id: str, tenant_id: str, version: int | None) -> dict[str, Any]:
        metadata = self._repository.get_secret(secret_id, tenant_id)
        if metadata is None or metadata["status"] != SecretStatus.ACTIVE.value:
            raise PermissionError("secret unavailable")
        selected_version = int(metadata["current_version"]) if version is None else int(version)
        row = self._repository.get_version(secret_id, selected_version)
        if row is None or row["status"] != SecretStatus.ACTIVE.value:
            raise PermissionError("secret version unavailable")
        return row

    def _retrieve_for_use(self, secret_id: str, tenant_id: str, secret_type: str,
                          version: int | None = None) -> tuple[bytearray, int]:
        row = self._resolve_version(secret_id, tenant_id, version)
        aad = self._aad(secret_id, tenant_id, secret_type, int(row["version"]))
        dek = self._key_manager.unwrap_dek(
            row["encrypted_dek"], row["dek_auth_tag"], row["dek_nonce"], aad, row["kek_version"]
        )
        sealed = row["ciphertext"] + row["auth_tag"]
        plaintext = _aesgcm()(dek).decrypt(row["nonce"], sealed, aad)
        return bytearray(plaintext), int(row["version"])

    def execute_with_secret(self, secret_id: str, tenant_id: str, secret_type: str,
                            version: int | None, callback: Callable[[memoryview], Any]) -> tuple[Any, int]:
        material, resolved_version = self._retrieve_for_use(secret_id, tenant_id, secret_type, version)
        try:
            return callback(memoryview(material)), resolved_version
        finally:
            material[:] = b"\x00" * len(material)

    def rotate(self, secret_id: str, tenant_id: str, secret_type: SecretType,
               material: SecretMaterial) -> int:
        return self.store(secret_id, tenant_id, secret_type, material)

    def revoke(self, secret_id: str) -> bool:
        return self._repository.set_secret_status(secret_id, SecretStatus.REVOKED.value)

    def delete(self, secret_id: str, tenant_id: str) -> bool:
        return self._repository.delete_secret(secret_id, tenant_id)

