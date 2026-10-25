"""SecretGuard domain contracts. SecretDefinition contains metadata, never secret values."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


class Decision(StrEnum):
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    ALLOW = "ALLOW"


class SecretStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    QUARANTINED = "QUARANTINED"


class SecretType(StrEnum):
    OPENAI_API_KEY = "OPENAI_API_KEY"
    ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"
    GOOGLE_API_KEY = "GOOGLE_API_KEY"
    GEMINI_API_KEY = "GEMINI_API_KEY"
    GROQ_API_KEY = "GROQ_API_KEY"
    MISTRAL_API_KEY = "MISTRAL_API_KEY"
    COHERE_API_KEY = "COHERE_API_KEY"
    TOGETHER_API_KEY = "TOGETHER_API_KEY"
    REPLICATE_API_TOKEN = "REPLICATE_API_TOKEN"
    HUGGINGFACE_API_KEY = "HUGGINGFACE_API_KEY"
    HF_TOKEN = "HF_TOKEN"
    AZURE_OPENAI_API_KEY = "AZURE_OPENAI_API_KEY"
    AZURE_OPENAI_ENDPOINT = "AZURE_OPENAI_ENDPOINT"
    OPENAI_EMBEDDING_API_KEY = "OPENAI_EMBEDDING_API_KEY"
    VOYAGE_API_KEY = "VOYAGE_API_KEY"
    COHERE_EMBED_API_KEY = "COHERE_EMBED_API_KEY"
    DATABASE_URL = "DATABASE_URL"
    POSTGRES_URL = "POSTGRES_URL"
    MONGODB_URI = "MONGODB_URI"
    MONGO_URL = "MONGO_URL"
    REDIS_URL = "REDIS_URL"
    REDIS_PASSWORD = "REDIS_PASSWORD"
    UPSTASH_REDIS_REST_TOKEN = "UPSTASH_REDIS_REST_TOKEN"
    PINECONE_API_KEY = "PINECONE_API_KEY"
    PINECONE_ENVIRONMENT = "PINECONE_ENVIRONMENT"
    QDRANT_API_KEY = "QDRANT_API_KEY"
    QDRANT_URL = "QDRANT_URL"
    WEAVIATE_API_KEY = "WEAVIATE_API_KEY"
    WEAVIATE_URL = "WEAVIATE_URL"
    CHROMA_API_KEY = "CHROMA_API_KEY"
    SUPABASE_URL = "SUPABASE_URL"
    SUPABASE_ANON_KEY = "SUPABASE_ANON_KEY"
    SUPABASE_SERVICE_ROLE_KEY = "SUPABASE_SERVICE_ROLE_KEY"
    NEON_DATABASE_URL = "NEON_DATABASE_URL"
    AWS_ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID"
    AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
    S3_BUCKET_NAME = "S3_BUCKET_NAME"
    CLOUDFLARE_R2_ACCESS_KEY_ID = "CLOUDFLARE_R2_ACCESS_KEY_ID"
    R2_SECRET_ACCESS_KEY = "R2_SECRET_ACCESS_KEY"
    GCS_SERVICE_ACCOUNT_JSON = "GCS_SERVICE_ACCOUNT_JSON"
    TAVILY_API_KEY = "TAVILY_API_KEY"
    SERPAPI_API_KEY = "SERPAPI_API_KEY"
    SERPER_API_KEY = "SERPER_API_KEY"
    BRAVE_SEARCH_API_KEY = "BRAVE_SEARCH_API_KEY"
    EXA_API_KEY = "EXA_API_KEY"
    FIRECRAWL_API_KEY = "FIRECRAWL_API_KEY"
    E2B_API_KEY = "E2B_API_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    GITHUB_PAT = "GITHUB_PAT"
    GITLAB_TOKEN = "GITLAB_TOKEN"
    TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
    SLACK_BOT_TOKEN = "SLACK_BOT_TOKEN"
    SLACK_SIGNING_SECRET = "SLACK_SIGNING_SECRET"
    DISCORD_BOT_TOKEN = "DISCORD_BOT_TOKEN"
    TWILIO_ACCOUNT_SID = "TWILIO_ACCOUNT_SID"
    TWILIO_AUTH_TOKEN = "TWILIO_AUTH_TOKEN"
    SENDGRID_API_KEY = "SENDGRID_API_KEY"
    RESEND_API_KEY = "RESEND_API_KEY"
    WHATSAPP_TOKEN = "WHATSAPP_TOKEN"
    WHATSAPP_PHONE_NUMBER_ID = "WHATSAPP_PHONE_NUMBER_ID"
    JWT_SECRET = "JWT_SECRET"
    JWT_PRIVATE_KEY = "JWT_PRIVATE_KEY"
    NEXTAUTH_SECRET = "NEXTAUTH_SECRET"
    AUTH_SECRET = "AUTH_SECRET"
    SESSION_SECRET = "SESSION_SECRET"
    ENCRYPTION_KEY = "ENCRYPTION_KEY"
    AES_SECRET_KEY = "AES_SECRET_KEY"
    OAUTH_GOOGLE_CLIENT_SECRET = "OAUTH_GOOGLE_CLIENT_SECRET"
    OAUTH_GITHUB_CLIENT_SECRET = "OAUTH_GITHUB_CLIENT_SECRET"
    STRIPE_WEBHOOK_SECRET = "STRIPE_WEBHOOK_SECRET"
    CLERK_WEBHOOK_SECRET = "CLERK_WEBHOOK_SECRET"
    STRIPE_SECRET_KEY = "STRIPE_SECRET_KEY"
    STRIPE_PUBLISHABLE_KEY = "STRIPE_PUBLISHABLE_KEY"
    LANGCHAIN_API_KEY = "LANGCHAIN_API_KEY"
    LANGSMITH_API_KEY = "LANGSMITH_API_KEY"
    LANGFUSE_SECRET_KEY = "LANGFUSE_SECRET_KEY"
    LANGFUSE_PUBLIC_KEY = "LANGFUSE_PUBLIC_KEY"
    HELICONE_API_KEY = "HELICONE_API_KEY"
    SENTRY_DSN = "SENTRY_DSN"
    SENTRY_AUTH_TOKEN = "SENTRY_AUTH_TOKEN"
    POSTHOG_API_KEY = "POSTHOG_API_KEY"


@dataclass(frozen=True)
class SecretDefinition:
    """Developer-owned metadata for an expected secret; it stores no material."""

    name: str
    secret_type: SecretType
    source: str
    operations: frozenset[str] = frozenset()
    destinations: frozenset[str] = frozenset()
    allowed: bool = True
    exposed: bool = False
    secret_id: str = ""

    def __post_init__(self) -> None:
        if not self.name or not self.source:
            raise ValueError("secret name and source are required")
        object.__setattr__(self, "operations", frozenset(str(v).lower() for v in self.operations))
        object.__setattr__(self, "destinations", frozenset(str(v).lower() for v in self.destinations))


@dataclass(frozen=True)
class SecretMaterial:
    """Runtime-only plaintext input. Never serialize, log, or persist this object."""

    value: bytearray = field(repr=False, compare=False)

    @classmethod
    def from_value(cls, value: str | bytes | bytearray) -> "SecretMaterial":
        raw = value if isinstance(value, bytearray) else bytearray(value.encode() if isinstance(value, str) else value)
        if not raw:
            raise ValueError("secret material cannot be empty")
        return cls(raw)

    def clear(self) -> None:
        self.value[:] = b"\x00" * len(self.value)

    def __repr__(self) -> str:
        return "SecretMaterial(<redacted>)"


class SecretRegistry:
    """Application-owned metadata registry. Secret values are not accepted."""

    def __init__(self) -> None:
        self._secrets: dict[str, SecretDefinition] = {}

    @property
    def secrets(self) -> Mapping[str, SecretDefinition]:
        return MappingProxyType(self._secrets)

    def register(self, definition: SecretDefinition) -> None:
        if not definition.secret_id:
            raise ValueError("secret_id is required before registry registration")
        if definition.secret_id in self._secrets:
            raise ValueError("secret_id is already registered")
        self._secrets[definition.secret_id] = definition

    def resolve(self, secret_id: str) -> SecretDefinition:
        return self._secrets[secret_id]


@dataclass(frozen=True)
class SecretAccessRequest:
    request_id: str
    secret_id: str
    tenant_id: str
    requester: str
    agent_id: str
    session_id: str
    tool_id: str
    purpose: str
    operation: str
    destination: str
    version: int | None = None


@dataclass(frozen=True)
class SecretSecurityContext:
    """Authenticated context created by the application, not by the agent."""

    tenant_id: str
    requester: str
    agent_id: str
    session_id: str
    authorized_tools: frozenset[str]

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.requester, self.agent_id, self.session_id)):
            raise ValueError("trusted secret security identity fields are required")
        object.__setattr__(self, "authorized_tools", frozenset(self.authorized_tools))


@dataclass(frozen=True)
class SecretGuard:
    secret_id: str
    decision: Decision
    timestamp: str
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecretPermissions:
    unregistered: bool = False
    allowed_use: bool = False
    allowed_type: frozenset[SecretType] = frozenset()
    allowed_destination: frozenset[str] = frozenset()
    allowed_operations: frozenset[str] = frozenset()
    allowed_exposed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_type", frozenset(self.allowed_type))
        object.__setattr__(self, "allowed_destination", frozenset(v.lower() for v in self.allowed_destination))
        object.__setattr__(self, "allowed_operations", frozenset(v.lower() for v in self.allowed_operations))
