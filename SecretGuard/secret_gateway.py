
from dataclasses import replace
import hashlib
from typing import Any, Callable
import uuid
import json

from SecretGuard.db import SecretRepository
from SecretGuard.secret_guard import SecretGuard, SecretVault, _utcnow
from .config import (
    Decision,
    SecretAccessRequest,
    SecretDefinition,
    SecretGuard as SecretGuardDecision,
    SecretMaterial,
    SecretPermissions,
    SecretRegistry,
    SecretSecurityContext,
    SecretStatus,
    SecretType,
)

class SecretBroker:
    """Mandatory application gateway; callers cannot access Vault retrieval."""

    def __init__(self, repository: SecretRepository, vault: SecretVault,
                 permissions: SecretPermissions | None = None, guard: SecretGuard | None = None) -> None:
        self._repository = repository
        self._vault = vault
        self._permissions = permissions or SecretPermissions()
        self._guard = guard or SecretGuard()
        self.registry = SecretRegistry()

    def register_secret(self, definition: SecretDefinition, material: SecretMaterial,
                        tenant_id: str, permissions: SecretPermissions) -> tuple[str, int]:
        secret_id = definition.secret_id or str(uuid.uuid4())
        definition = replace(definition, secret_id=secret_id)
        decision = self._guard.evaluate_store(definition, permissions)
        if decision.decision is not Decision.ALLOW:
            material.clear()
            raise PermissionError("secret registration denied")
        metadata = {
            "name": definition.name,
            "secret_type": definition.secret_type.value,
            "source": definition.source,
            "allowed": definition.allowed,
            "exposed": definition.exposed,
        }
        try:
            self._repository.register_definition(metadata, tenant_id, secret_id)
            self._repository.save_permissions(secret_id, tenant_id, {
                "operations": permissions.allowed_operations,
                "destinations": permissions.allowed_destination,
                "types": [item.value for item in permissions.allowed_type],
                "allowed_use": permissions.allowed_use,
                "allowed_exposed": permissions.allowed_exposed,
                "unregistered": permissions.unregistered,
            })
            self.registry.register(definition)
            version = self._vault.store(secret_id, tenant_id, definition.secret_type, material)
            return secret_id, version
        except Exception:
            material.clear()
            self._repository.set_secret_status(secret_id, SecretStatus.QUARANTINED.value)
            raise

    def execute_with_secret(self, request: SecretAccessRequest, context: SecretSecurityContext,
                            callback: Callable[[memoryview], Any]) -> Any:
        if not isinstance(context, SecretSecurityContext) or not self._context_matches(request, context):
            denied = SecretGuardDecision(request.secret_id, Decision.DENY, _utcnow(), ("trusted_context_mismatch",))
            self._audit(request, None, denied, request.version, False, context)
            raise PermissionError("secret access denied")
        metadata = self._repository.get_secret(request.secret_id, request.tenant_id)
        permission_row = self._repository.get_permissions(request.secret_id, request.tenant_id)
        definition = self._definition_from_row(metadata, permission_row) if metadata else None
        permissions = self._permissions_from_row(permission_row) if permission_row else self._permissions
        status = metadata["status"] if metadata else None
        decision = self._guard.evaluate_access(definition, permissions, request, status)
        if decision.decision is not Decision.ALLOW or definition is None:
            self._audit(request, definition, decision, None, False, context)
            raise PermissionError("secret access denied")
        try:
            result, resolved_version = self._vault.execute_with_secret(
                request.secret_id, request.tenant_id, definition.secret_type.value,
                request.version, callback,
            )
            self._audit(request, definition, decision, resolved_version, True, context)
            return result
        except PermissionError as error:
            self._audit(request, definition, decision, None, False, context)
            raise error
        except Exception:
            self._audit(request, definition, decision, None, False, context)
            raise RuntimeError("secret operation failed") from None

    def rotate(self, request: SecretAccessRequest, context: SecretSecurityContext, material: SecretMaterial) -> int:
        if not self._context_matches(request, context):
            material.clear()
            raise PermissionError("secret rotation denied")
        definition, permissions, decision = self._authorize_request(request)
        if decision.decision is not Decision.ALLOW or definition is None:
            material.clear()
            raise PermissionError("secret rotation denied")
        version = self._vault.rotate(request.secret_id, request.tenant_id, definition.secret_type, material)
        self._audit(request, definition, decision, version, True, context)
        return version

    def revoke(self, request: SecretAccessRequest, context: SecretSecurityContext,
               operation: str = "revoke") -> bool:
        if not isinstance(context, SecretSecurityContext) or not self._context_matches(request, context):
            raise PermissionError("secret revocation denied")
        if operation not in {"delete", "revoke"}:
            raise ValueError("secret revocation operation must be delete or revoke")
        definition, _, decision = self._authorize_request(request, operation=operation)
        if decision.decision is not Decision.ALLOW:
            raise PermissionError("secret revocation denied")
        if operation == "delete":
            result = self._vault.delete(request.secret_id, request.tenant_id)
            self._audit(request, definition, decision, None, result, context)
            return result
        result = self._vault.revoke(request.secret_id)
        self._audit(request, definition, decision, None, result, context)
        return result

    @staticmethod
    def _context_matches(request: SecretAccessRequest, context: SecretSecurityContext) -> bool:
        if not isinstance(context, SecretSecurityContext):
            return False
        return (
            request.tenant_id == context.tenant_id
            and request.requester == context.requester
            and request.agent_id == context.agent_id
            and request.session_id == context.session_id
            and request.tool_id in context.authorized_tools
        )

    def _authorize_request(self, request: SecretAccessRequest, operation: str | None = None):
        metadata = self._repository.get_secret(request.secret_id, request.tenant_id)
        row = self._repository.get_permissions(request.secret_id, request.tenant_id)
        definition = self._definition_from_row(metadata, row) if metadata else None
        permissions = self._permissions_from_row(row) if row else self._permissions
        normalized_request = replace(request, operation=operation) if operation else request
        decision = self._guard.evaluate_access(definition, permissions, normalized_request, metadata["status"] if metadata else None)
        return definition, permissions, decision

    @staticmethod
    def _definition_from_row(row: dict[str, Any] | None, policy_row: dict[str, Any] | None = None) -> SecretDefinition | None:
        if row is None:
            return None
        policy = policy_row or {}
        return SecretDefinition(row["name"], SecretType(row["secret_type"]), row["source"],
                                frozenset(json.loads(policy.get("operations", "[]"))),
                                frozenset(json.loads(policy.get("destinations", "[]"))),
                                bool(row["allowed"]), bool(row["exposed"]), row["secret_id"])

    @staticmethod
    def _permissions_from_row(row: dict[str, Any] | None) -> SecretPermissions:
        if row is None:
            return SecretPermissions()
        return SecretPermissions(
            unregistered=bool(row["allow_unregistered"]),
            allowed_use=bool(row["allowed_use"]),
            allowed_type=frozenset(SecretType(item) for item in json.loads(row["allowed_types"])),
            allowed_destination=frozenset(json.loads(row["destinations"])),
            allowed_operations=frozenset(json.loads(row["operations"])),
            allowed_exposed=bool(row["allowed_exposed"]),
        )

    def _audit(self, request: SecretAccessRequest, definition: SecretDefinition | None,
             decision: SecretGuardDecision, version: int | None, success: bool,
             context: SecretSecurityContext | None = None) -> None:
        purpose_hash = hashlib.sha256(request.purpose.encode()).hexdigest() if request.purpose else ""
        self._repository.audit({
            "event_id": str(uuid.uuid4()), "request_id": request.request_id,
            "secret_id": request.secret_id, "secret_type": definition.secret_type.value if definition else "UNKNOWN",
            "secret_version": version, "requester": context.requester if context else request.requester,
            "agent_id": context.agent_id if context else request.agent_id,
            "session_id": context.session_id if context else request.session_id, "tool_id": request.tool_id,
            "operation": request.operation, "destination": request.destination,
            "decision": decision.decision.value, "reason_codes": decision.reason_codes,
            "purpose_hash": purpose_hash, "key_version": self._vault._key_manager.get_current_key_version(),
            "success": success, "timestamp": _utcnow(),
        })
