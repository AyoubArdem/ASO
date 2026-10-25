from dataclasses import dataclass
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class MetaAgentConfig:
    """Persistent, non-secret metadata describing an agent."""

    agent_id: str
    agent_name: str
    agent_version: str
    agent_developper: str
    agent_description: str


@dataclass(frozen=True)
class Infos:
    """Correlation identifiers for an agent session and its tasks."""

    id: str
    agent: str
    session_id: str
    request_id: str
    task_id: str


@dataclass(frozen=True)
class LLM_Query_audit:
    """Structured, non-secret record of a component decision."""

    id: str
    agent: str
    component: str
    action: str
    reasons: tuple[str, ...]


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"


class Framework(StrEnum):
    LANGCHAIN = "LANGCHAIN"
    CREWAI = "CREWAI"
    AUTOGEN_MICROSOFT = "AUTOGEN_MICROSOFT"
    GOOGLE_AGENT = "GOOGLE_AGENT"
    OPENAI_SDK = "OPENAI_SDK"
    LLAMAINDEX = "LLAMAINDEX"
    PYDANTIC_AI = "PYDANTIC_AI"


@dataclass(frozen=True)
class ToolSecurityContext:
    """Host-authenticated identity and tool allowlist for a tool request."""

    agent_id: str
    session_id: str
    authorized_tools: frozenset[str]

    def __post_init__(self) -> None:
        if not self.agent_id or not self.session_id:
            raise ValueError("trusted tool identity fields are required")
        object.__setattr__(self, "authorized_tools", frozenset(self.authorized_tools))


@dataclass(frozen=True)
class OrchestrationResult:
    request_id: str
    component: str
    decision: str
    data: Any = None
    reason_codes: tuple[str, ...] = ()

