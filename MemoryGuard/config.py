
import os
from typing import Any, Mapping, TypedDict
from dataclasses import dataclass, field
from enum import StrEnum
import uuid


class Operation(StrEnum):
        READ = "read"
        SEARCH = "search"
        WRITE = "write"
        UPDATE = "update"
        DELETE = "delete"


class Decision(StrEnum):
        ALLOW = "ALLOW"
        DENY = "DENY"
        QUARANTINE = "QUARANTINE"


class MemoryStatus(StrEnum):
        ACTIVE = "ACTIVE"
        QUARANTINED = "QUARANTINED"
        REJECTED = "REJECTED"
        DELETED = "DELETED"


@dataclass(frozen=True)
class SecurityContext:
        """Trusted context created by the host authentication layer."""

        agent_id: str
        tenant_id: str
        allowed_stores: frozenset[str]
        permissions: frozenset[str]
        session_id: str = ""
        policies: Mapping[str, Any] = None

        def __post_init__(self) -> None:
                if not self.agent_id or not self.tenant_id or not self.session_id:
                        raise ValueError("trusted identity fields are required")
                object.__setattr__(self, "allowed_stores", frozenset(self.allowed_stores))
                object.__setattr__(self, "permissions", frozenset(self.permissions))
                object.__setattr__(self, "policies", dict(self.policies or {}))


@dataclass(frozen=True)
class StoreConfig:
        store_id: str
        store_type: str
        provider: str
        adapter: Any
        memory_types: frozenset[str]
        capabilities: frozenset[str]
        enabled: bool = True
        metadata: Mapping[str, Any] = None

        def __post_init__(self) -> None:
                if not self.store_id or not self.provider or self.adapter is None:
                        raise ValueError("store_id, provider, and adapter are required")
                object.__setattr__(self, "memory_types", frozenset(self.memory_types))
                object.__setattr__(self, "capabilities", frozenset(self.capabilities))
                object.__setattr__(self, "metadata", dict(self.metadata or {}))


@dataclass(frozen=True)
class ProviderCredentials:
        """Application-owned credential reference; secret values are never agent data."""

        provider: str
        endpoint: str | None = None
        api_key_env: str | None = None
        access_key_env: str | None = None
        secret_key_env: str | None = None
        region_env: str | None = None
        require_tls: bool = True
        timeout_seconds: float = 10.0

        def resolve(self) -> dict[str, Any]:
                endpoint = self.endpoint or os.environ.get(f"{self.provider.upper()}_URL")
                api_key = os.environ.get(self.api_key_env) if self.api_key_env else None
                access_key = os.environ.get(self.access_key_env) if self.access_key_env else None
                secret_key = os.environ.get(self.secret_key_env) if self.secret_key_env else None
                region = os.environ.get(self.region_env) if self.region_env else None
                if self.require_tls and endpoint and endpoint.startswith("http://"):
                        raise ValueError(f"TLS is required for provider endpoint: {self.provider}")
                if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
                        raise ValueError("timeout_seconds must be between 0 and 120")
                return {
                        "provider": self.provider,
                        "endpoint": endpoint,
                        "api_key": api_key,
                        "access_key": access_key,
                        "secret_key": secret_key,
                        "region": region,
                        "timeout_seconds": self.timeout_seconds,
                }


@dataclass(frozen=True)
class MemoryRequest:
        agent_id: str
        operation: Operation | str
        store_id: str
        request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
        payload: Any = None
        query: str | None = None
        limit: int = 10
        filters: Mapping[str, Any] = None
        memory_type: str = "default"
        metadata: Mapping[str, Any] = None

        def __post_init__(self) -> None:
                operation = Operation(self.operation)
                if not self.agent_id or not self.request_id or not self.store_id:
                        raise ValueError("agent_id, request_id, and store_id are required")
                if self.limit < 1 or self.limit > 1000:
                        raise ValueError("limit must be between 1 and 1000")
                object.__setattr__(self, "operation", operation)
                object.__setattr__(self, "filters", dict(self.filters or {}))
                object.__setattr__(self, "metadata", dict(self.metadata or {}))


@dataclass(frozen=True)
class GuardDecision:
        decision: Decision
        risk_score: float
        reason_codes: tuple[str, ...] = ()
        phase: str = "pre"


@dataclass(frozen=True)
class AuditEvent:
        event_id: str
        request_id: str
        timestamp: str
        agent_id: str
        tenant_id: str
        operation: str
        store_id: str
        store_type: str
        provider: str
        decision: str
        risk_score: float
        reason_codes: tuple[str, ...] = ()
        result_count: int = 0
        latency_ms: float = 0.0

class payload(TypedDict):
    data : str
    metadata : dict


@dataclass(frozen=True)
class AgentRequest:
        agent_id : str
        operation : str
        store : str
        permissions : list[str]
        session_id: str = ""
        request_id: str = ""
        agent_name: str = ""
        agent_version: str = ""
        agent_author: str = ""
        agent_description: str = ""
        data : Any = None
        memory_id : str | None = None
        query : str | None = None

@dataclass(frozen=True)
class GuardRequest:
        action_id : str
        agent : AgentRequest
        action : str
        risk_score : float
        confidence : float