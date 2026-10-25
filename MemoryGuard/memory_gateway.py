
import datetime
from typing import Any
import uuid

from MemoryGuard.config import AgentRequest, AuditEvent, Decision, GuardDecision, MemoryRequest, Operation, SecurityContext, StoreConfig
from MemoryGuard.memory_access_layer import AccessResult, AuditLog, QuarantineStore, StoreRegistry
from MemoryGuard.memory_guard import CyberAI, MemoryGuard


class GuardedMemoryAccessLayer:
    """Only public memory gateway exposed to an AI-agent host."""

    def __init__(
        self,
        registry: StoreRegistry,
        cyber_ai: CyberAI | None = None,
        audit_log: AuditLog | None = None,
        quarantine_store: QuarantineStore | None = None,
    ) -> None:
        self._registry = registry
        self._cyber_ai = cyber_ai or CyberAI()
        self._audit = audit_log or AuditLog()
        self._quarantine = quarantine_store or QuarantineStore()

    @property
    def audit_log(self) -> tuple[AuditEvent, ...]:
        return self._audit.snapshot()

    def execute(self, request: MemoryRequest, context: SecurityContext) -> AccessResult:
        started = datetime.datetime.now(datetime.timezone.utc)
        if not isinstance(request, MemoryRequest):
            return AccessResult("", Decision.DENY, reason_codes=("invalid_memory_request",))
        if not isinstance(context, SecurityContext):
            return AccessResult(request.request_id, Decision.DENY, reason_codes=("trusted_memory_context_required",))
        try:
            store = self._registry.resolve(request.store_id)
        except PermissionError:
            return AccessResult(request.request_id, Decision.DENY, reason_codes=("unknown_memory_store",))
        pre = self._pre_authorize(request, context, store)
        if pre.decision is not Decision.ALLOW:
            if pre.decision is Decision.QUARANTINE:
                self._quarantine.put(request.request_id, request.payload, pre.reason_codes)
            self._audit_event(request, context, store, pre, started)
            return AccessResult(request.request_id, pre.decision, reason_codes=pre.reason_codes)

        agent_request = AgentRequest(
            agent_id=context.agent_id,
            session_id=context.session_id,
            request_id=request.request_id,
            operation=request.operation.value,
            store=request.store_id,
            permissions=list(context.permissions),
            data=request.payload if request.operation in {Operation.WRITE, Operation.UPDATE} else request.query,
            memory_id=request.metadata.get("memory_id"),
            query=request.query,
        )
        method_name = "search" if request.operation is Operation.SEARCH else request.operation.value
        try:
            receipt = getattr(store.adapter, method_name)(agent_request, "pre-authorized")
        except Exception:
            post = GuardDecision(Decision.QUARANTINE, 1.0, ("adapter_failure",), "post")
            self._audit_event(request, context, store, post, started)
            return AccessResult(request.request_id, post.decision, reason_codes=post.reason_codes)

        if not receipt.completed:
            decision = GuardDecision(Decision.DENY, 1.0, ("adapter_rejected",), "post")
            self._audit_event(request, context, store, decision, started)
            return AccessResult(request.request_id, decision.decision, reason_codes=decision.reason_codes)

        if request.operation in {Operation.READ, Operation.SEARCH} and receipt.data is not None:
            post = self._post_inspect(receipt.data, context)
            if post.decision is not Decision.ALLOW:
                if post.decision is Decision.QUARANTINE:
                    self._quarantine.put(request.request_id, receipt.data, post.reason_codes)
                self._audit_event(request, context, store, post, started)
                return AccessResult(request.request_id, post.decision, reason_codes=post.reason_codes)

        allowed = GuardDecision(Decision.ALLOW, 0.0, (), "post")
        self._audit_event(request, context, store, allowed, started, receipt.data)
        return AccessResult(request.request_id, Decision.ALLOW, receipt.data, (), receipt.operation_id)

    def _pre_authorize(self, request: MemoryRequest, context: SecurityContext, store: StoreConfig) -> GuardDecision:
        if not store.enabled:
            return GuardDecision(Decision.DENY, 1.0, ("store_disabled",))
        if request.agent_id != context.agent_id:
            return GuardDecision(Decision.DENY, 1.0, ("trusted_identity_mismatch",))
        if request.store_id not in context.allowed_stores:
            return GuardDecision(Decision.DENY, 1.0, ("unauthorized_memory_scope",))
        operation = request.operation.value
        allowed_operations = set(context.permissions)
        if operation == Operation.SEARCH.value and "read" in allowed_operations:
            allowed_operations.add(operation)
        if operation not in allowed_operations or operation not in store.capabilities:
            return GuardDecision(Decision.DENY, 1.0, ("operation_not_permitted",))
        if request.memory_type not in store.memory_types and "*" not in store.memory_types:
            return GuardDecision(Decision.DENY, 1.0, ("memory_type_not_permitted",))
        payload = request.payload if request.payload is not None else request.query or ""
        guard_permissions = set(context.permissions)
        guard_permissions.add("read" if request.operation is Operation.SEARCH else operation)
        metadata = {"permissions": list(guard_permissions), "agent_id": context.agent_id}
        guard = MemoryGuard(
            action="read" if request.operation is Operation.SEARCH else operation,
            source={"data": payload, "metadata": metadata},
            infos=metadata,
            cyber_ai=self._cyber_ai,
        )
        return guard.evaluate()

    def _post_inspect(self, data: Any, context: SecurityContext) -> GuardDecision:
        metadata = {"permissions": ["read"], "agent_id": context.agent_id}
        guard = MemoryGuard(
            action="read",
            source={"data": data, "metadata": metadata},
            infos=metadata,
            cyber_ai=self._cyber_ai,
        )
        decision = guard.evaluate()
        return GuardDecision(
            decision.decision,
            decision.risk_score,
            decision.reason_codes or ("untrusted_retrieved_memory",),
            "post",
        )

    def _audit_event(self, request: MemoryRequest, context: SecurityContext, store: StoreConfig,
                     decision: GuardDecision, started: datetime, data: Any = None) -> None:
        latency = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000
        self._audit.append(AuditEvent(
            event_id=str(uuid.uuid4()), request_id=request.request_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(), agent_id=context.agent_id,
            tenant_id=context.tenant_id, session_id=context.session_id,
            operation=request.operation.value, store_id=store.store_id,
            store_type=store.store_type, provider=store.provider,
            decision=decision.decision.value, risk_score=decision.risk_score,
            reason_codes=decision.reason_codes,
            result_count=1 if data is not None else 0, latency_ms=latency,
        ))
