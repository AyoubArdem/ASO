"""Public Tool Guard contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"
    ALLOW_RESULT = "ALLOW_RESULT"
    SANITIZE = "SANITIZE"
    DENY_RESULT = "DENY_RESULT"


@dataclass(frozen=True)
class ToolDefinition:
    tool_id: str
    name: str
    description: str
    purpose: str
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    expected_output: str = ""
    operations: frozenset[str] = frozenset()
    side_effects: frozenset[str] = frozenset()
    required_capabilities: frozenset[str] = frozenset()
    allowed_resources: frozenset[str] = frozenset()
    forbidden_operations: frozenset[str] = frozenset()
    sensitivity: str = "normal"
    risk_characteristics: frozenset[str] = frozenset()
    execution_constraints: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tool_id or not self.name or not self.description or not self.purpose:
            raise ValueError("tool_id, name, description, and purpose are required")
        object.__setattr__(self, "operations", frozenset(self.operations))
        object.__setattr__(self, "side_effects", frozenset(self.side_effects))
        object.__setattr__(self, "required_capabilities", frozenset(self.required_capabilities))
        object.__setattr__(self, "allowed_resources", frozenset(self.allowed_resources))
        object.__setattr__(self, "forbidden_operations", frozenset(self.forbidden_operations))
        object.__setattr__(self, "risk_characteristics", frozenset(self.risk_characteristics))
        object.__setattr__(self, "input_schema", _freeze(self.input_schema))
        object.__setattr__(self, "output_schema", _freeze(self.output_schema))
        object.__setattr__(self, "execution_constraints", _freeze(self.execution_constraints))


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    agent_id: str
    session_id: str
    task_id: str
    tool_id: str
    purpose: str
    reason: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    task_context: str = ""
    previous_tool_context: tuple[str, ...] = ()
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not all((self.request_id, self.agent_id, self.session_id, self.task_id, self.tool_id)):
            raise ValueError("request_id, agent_id, session_id, task_id, and tool_id are required")
        object.__setattr__(self, "arguments", _freeze(self.arguments))
        object.__setattr__(self, "previous_tool_context", tuple(self.previous_tool_context))


@dataclass(frozen=True)
class ToolDecision:
    request_id: str
    action: str
    decision: Decision
    risk_score: float
    reasons: tuple[str, ...] = ()
    triggered_rules: tuple[str, ...] = ()
    relevant_features: Mapping[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    phase: str = "pre"

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "triggered_rules", tuple(self.triggered_rules))
        object.__setattr__(self, "relevant_features", _freeze(self.relevant_features))


@dataclass(frozen=True)
class ToolExecutionRecord:
    request_id: str
    tool_id: str
    started_at: str
    ended_at: str
    duration_ms: float
    success: bool
    error: str = ""
    output_type: str = ""
    output_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolHistory:
    request_id: str
    tool_id: str
    pre_decision: Decision
    pre_risk_score: float
    post_decision: Decision
    post_risk_score: float
    trusted: bool = False


@dataclass(frozen=True)
class ToolResult:
    request_id: str
    decision: Decision
    data: Any = None
    reasons: tuple[str, ...] = ()
    execution: ToolExecutionRecord | None = None
