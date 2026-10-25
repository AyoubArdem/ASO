"""Mandatory pre/post security boundary for AI-agent tool execution."""

from __future__ import annotations

from PromptGuard.prompt_inspection import __Feature_Extraction__
import hashlib
import inspect
import json
import sqlite3
import time
import uuid
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .config import Decision, ToolDecision, ToolDefinition, ToolExecutionRecord, ToolRequest, ToolResult
from .db import EncryptedField
from DecisionEngine.config import ToolSecurityContext


def _safe_value(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _safe_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_value(item) for item in value]
    return value


class ToolRegistry:
    """Developer-owned definitions and executable functions."""

    def __init__(self) -> None:
        self._tools: dict[str, tuple[ToolDefinition, Callable[..., Any]]] = {}

    def register(self, definition: ToolDefinition, implementation: Callable[..., Any]) -> None:
        if not callable(implementation):
            raise TypeError("tool implementation must be callable")
        if definition.tool_id in self._tools:
            raise ValueError(f"tool already registered: {definition.tool_id}")
        self._tools[definition.tool_id] = (definition, implementation)

    def resolve(self, tool_id: str) -> tuple[ToolDefinition, Callable[..., Any]]:
        try:
            return self._tools[tool_id]
        except KeyError as error:
            raise PermissionError("tool is not registered") from error


class ToolAuditStore:
    """Internal append-only audit storage; raw tool results are not persisted."""

    def __init__(self, database_path: str = "tool_guard.db", encryption_key: str | bytes | None = None) -> None:
        self.cipher = EncryptedField(encryption_key)
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS tool_audit (
                event_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL, tool_id TEXT NOT NULL,
                phase TEXT NOT NULL, decision TEXT NOT NULL,
                risk_score REAL NOT NULL, reasons TEXT NOT NULL,
                timestamp TEXT NOT NULL, metadata TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def record(self, decision: ToolDecision, agent_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO tool_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), decision.request_id, agent_id, decision.action,
                 decision.phase, decision.decision.value, decision.risk_score,
                 self.cipher.encrypt(decision.reasons), decision.timestamp,
                 self.cipher.encrypt(dict(decision.relevant_features))),
            )

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        rows = self.connection.execute(
            "SELECT request_id, agent_id, tool_id, phase, decision, risk_score, reasons, timestamp FROM tool_audit"
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def close(self) -> None:
        self.connection.close()


class ToolGuard:
    """Executes registered tools only after pre- and post-security analysis."""

    def __init__(self, registry: ToolRegistry | None = None, audit: ToolAuditStore | None = None,
                 llm_analyser: Callable[[str, Mapping[str, Any]], Any] | None = None,
                 *, trusted_context: ToolSecurityContext | None = None) -> None:
        self.registry = registry or ToolRegistry()
        self.audit = audit or ToolAuditStore()
        self.llm_analyser = llm_analyser
        self.trusted_context = trusted_context
        self._history: list[ToolRequest] = []
        self._quarantine: list[dict[str, Any]] = []

    def pre_guard(self, request: ToolRequest) -> ToolDecision:
        timestamp = datetime.now(timezone.utc).isoformat()
        reasons: list[str] = []
        features: dict[str, Any] = {"argument_count": len(request.arguments), "history_length": len(self._history)}
        try:
            definition, _ = self.registry.resolve(request.tool_id)
        except PermissionError:
            result = self._decision(request, Decision.DENY, 1.0, ("unknown_tool",), features, timestamp)
            self.audit.record(result, request.agent_id)
            return result

        requested_operation = str(request.arguments.get("operation", "")).lower()
        declared_operations = {operation.lower() for operation in definition.operations}
        if declared_operations and requested_operation not in declared_operations:
            reasons.append("operation_not_declared")
        if definition.forbidden_operations & set(map(str, request.arguments.values())):
            reasons.append("forbidden_operation")
        if definition.allowed_resources:
            resources = {str(value) for value in request.arguments.values()}
            if resources.isdisjoint(definition.allowed_resources):
                reasons.append("resource_out_of_scope")
        if not request.purpose.strip() or not request.reason.strip():
            reasons.append("missing_purpose_or_reason")
        suspicious = self._suspicious_text(request.purpose + " " + request.reason + " " + json.dumps(request.arguments, default=str))
        if suspicious:
            reasons.append("suspicious_request_content")
            features["suspicious_patterns"] = suspicious
        if len(request.previous_tool_context) > 50:
            reasons.append("tool_chain_too_long")

        if reasons:
            decision = Decision.DENY if any(reason in reasons for reason in ("unknown_tool", "forbidden_operation", "resource_out_of_scope")) else Decision.REVIEW
            result = self._decision(request, decision, min(1.0, 0.6 + len(reasons) * 0.1), tuple(reasons), features, timestamp)
        elif self.llm_analyser is not None:
            result = self._llm_decision(request, definition, features, timestamp)
        else:
            result = self._decision(request, Decision.ALLOW, 0.05, (), features, timestamp)
        self.audit.record(result, request.agent_id)
        return result

    def execute(self, request: ToolRequest, context: ToolSecurityContext | None = None) -> ToolResult:
        trusted_context = context or self.trusted_context
        if not isinstance(trusted_context, ToolSecurityContext):
            return self._deny_untrusted_request(request, "trusted_tool_context_required")
        if (
            request.agent_id != trusted_context.agent_id
            or request.session_id != trusted_context.session_id
            or request.tool_id not in trusted_context.authorized_tools
        ):
            return self._deny_untrusted_request(request, "trusted_identity_mismatch")

        pre = self.pre_guard(request)
        if pre.decision is not Decision.ALLOW:
            if pre.decision in {Decision.REVIEW, Decision.QUARANTINE}:
                self._quarantine.append({"request_id": request.request_id, "request": _safe_value(request), "decision": _safe_value(pre)})
            return ToolResult(request.request_id, pre.decision, reasons=pre.reasons)

        definition, implementation = self.registry.resolve(request.tool_id)
        started = datetime.now(timezone.utc)
        start = time.perf_counter()
        result: Any = None
        error = ""
        success = False
        try:
            result = self._invoke(implementation, request.arguments)
            success = True
        except Exception as exc:
            error = type(exc).__name__
        ended = datetime.now(timezone.utc)
        execution = ToolExecutionRecord(
            request.request_id, request.tool_id, started.isoformat(), ended.isoformat(),
            (time.perf_counter() - start) * 1000, success, error,
            type(result).__name__ if success else "", self._output_metadata(result) if success else {},
        )
        if not success:
            post = self._decision(request, Decision.QUARANTINE, 1.0, ("tool_execution_failed",), {"error": error}, ended.isoformat(), "post")
            self.audit.record(post, request.agent_id)
            return ToolResult(request.request_id, post.decision, reasons=post.reasons, execution=execution)

        post, safe_result = self.post_guard(request, definition, result, ended.isoformat())
        self.audit.record(post, request.agent_id)
        self._history.append(request)
        return ToolResult(request.request_id, post.decision, safe_result, post.reasons, execution)

    def _deny_untrusted_request(self, request: ToolRequest, reason: str) -> ToolResult:
        timestamp = datetime.now(timezone.utc).isoformat()
        decision = self._decision(request, Decision.DENY, 1.0, (reason,), {}, timestamp)
        self.audit.record(decision, request.agent_id)
        return ToolResult(request.request_id, decision.decision, reasons=decision.reasons)

    def post_guard(self, request: ToolRequest, definition: ToolDefinition, result: Any,
                   timestamp: str | None = None) -> tuple[ToolDecision, Any]:
        reasons: list[str] = []
        features = self._output_metadata(result)
        features["definition_purpose"] = definition.purpose
        features["expected_output"] = definition.expected_output
        if definition.output_schema and not self._matches_schema(result, definition.output_schema):
            reasons.append("output_schema_mismatch")
        if self._suspicious_text(json.dumps(result, default=str)):
            reasons.append("suspicious_tool_result")
        if self.llm_analyser is not None:
            llm_decision = self._llm_result_decision(request, definition, result, features, timestamp or "")
            if llm_decision is not None and llm_decision.decision is not Decision.ALLOW_RESULT:
                reasons.extend(llm_decision.reasons)
                features = dict(features)
                features["llm_result_review"] = True
        if reasons:
            self._quarantine.append({"request_id": request.request_id, "result": str(result), "reasons": reasons})
            return self._decision(request, Decision.QUARANTINE, 0.85, tuple(reasons), features, timestamp or "", "post"), None
        return self._decision(request, Decision.ALLOW_RESULT, 0.02, (), features, timestamp or "", "post"), result

    def _llm_result_decision(self, request: ToolRequest, definition: ToolDefinition,
                             result: Any, features: Mapping[str, Any], timestamp: str) -> ToolDecision | None:
        """Ask the configured model whether the untrusted result matches the definition."""
        payload = json.dumps({
            "stage": "post_execution",
            "tool_definition": _safe_value(definition),
            "tool_request": _safe_value(request),
            "raw_tool_result": result,
            "features": features,
        }, default=str)
        try:
            response = self.llm_analyser(payload, {"stage": "post_execution", **features})
            if not isinstance(response, Mapping):
                return self._decision(request, Decision.QUARANTINE, 1.0, ("invalid_llm_result_response",), features, timestamp, "post")
            decision_name = str(response.get("decision", "QUARANTINE")).upper()
            if decision_name == "ALLOW":
                decision_name = "ALLOW_RESULT"
            if decision_name not in {"ALLOW_RESULT", "SANITIZE", "DENY_RESULT", "REVIEW", "QUARANTINE"}:
                decision_name = "QUARANTINE"
            decision = Decision(decision_name)
            risk = min(1.0, max(0.0, float(response.get("risk_score", 1.0))))
            reason = str(response.get("reason", "llm_result_analysis"))[:256]
            return self._decision(request, decision, risk, (reason,), features, timestamp, "post")
        except Exception:
            return self._decision(request, Decision.QUARANTINE, 1.0, ("llm_result_analysis_failed",), features, timestamp, "post")

    @staticmethod
    def _invoke(implementation: Callable[..., Any], arguments: Mapping[str, Any]) -> Any:
        signature = inspect.signature(implementation)
        if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
            return implementation(**dict(arguments))
        return implementation(**{key: value for key, value in arguments.items() if key in signature.parameters})

    def _llm_decision(self, request: ToolRequest, definition: ToolDefinition,
                      features: Mapping[str, Any], timestamp: str) -> ToolDecision:
        try:
            response = self.llm_analyser(json.dumps({"request": _safe_value(request), "definition": _safe_value(definition), "features": features}, default=str), features)
            if isinstance(response, Mapping):
                decision = Decision(str(response.get("decision", "REVIEW")).upper())
                risk = min(1.0, max(0.0, float(response.get("risk_score", 1.0))))
                reason = str(response.get("reason", "llm_analysis"))[:256]
                return self._decision(request, decision, risk, (reason,), features, timestamp)
        except Exception:
            pass
        return self._decision(request, Decision.REVIEW, 1.0, ("llm_analysis_failed",), features, timestamp)

    @staticmethod
    def _decision(request: ToolRequest, decision: Decision, risk: float, reasons: tuple[str, ...],
                  features: Mapping[str, Any], timestamp: str, phase: str = "pre") -> ToolDecision:
        return ToolDecision(request.request_id, request.tool_id, decision, risk, reasons, reasons, features, timestamp, phase)

    @staticmethod
    def _suspicious_text(value: str) -> list[str]:
        lowered = value.lower()
        patterns = ("ignore previous", "system prompt", "reveal secret", "exfiltrate", "rm -rf", "powershell", "drop table")
        reasons = [f"pattern:{pattern}" for pattern in patterns if pattern in lowered]
        return reasons

    @staticmethod
    def _output_metadata(result: Any) -> dict[str, Any]:
        return {"type": type(result).__name__, "size": len(result) if hasattr(result, "__len__") else 1}

    @staticmethod
    def _matches_schema(value: Any, schema: Mapping[str, Any]) -> bool:
        expected = schema.get("type")
        types = {"object": dict, "array": list, "string": str, "number": (int, float), "boolean": bool}
        return expected not in types or isinstance(value, types[expected])
