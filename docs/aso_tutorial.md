# ASO Tutorial

This tutorial describes the current ASO API and shows how to put its guards between an agent and protected resources. ASO is a security-boundary library, not an agent framework:
 the application remains responsible for authenticating identities, selecting policies, configuring provider models, and keeping guard gateways on every path to a resource.

## Install

Install the published distribution and only the integrations you use:

```bash
python -m pip install "aso-security"
python -m pip install "aso-security[google]"
```

For a checkout, install development dependencies with `python -m pip install -e ".[dev]"`.

## Security Flow

1. The host authenticates the caller and constructs trusted identity context. Never build this context from agent-controlled text.
2. The host sends a typed request to `AgentSecurityOrchestrator.process`.
3. The configured `PromptAnalyser` inspects the request. Anything other than `ALLOW`, or an analysis failure, stops dispatch.
4. The matching resource gateway independently checks permissions and policy.
5. Only an authorized gateway invokes its adapter, registered tool, or secret callback.
6. The caller handles the typed result and reason codes without exposing credentials or audit data.

Prompt inspection is not authorization. Keep the resource-specific guard in front of the actual adapter or function, including when an agent framework has its own tool registry.

## Four Developer Entry Points

ASO exposes four main ways to run the security applications:

| Entry point | What it runs | Caller supplies |
| --- | --- | --- |
| `GuardedMemoryAccessLayer.execute(request, context)` | MemoryGuard authorization, adapter operation, retrieved-data inspection, audit/quarantine handling. | A registered store, a `MemoryRequest`, and a host-created `SecurityContext`. |
| `ToolGuard.execute(request)` | Tool pre-check, registered callable execution, result post-check, and audit. | A `ToolRequest` and a registry that maps its tool ID to a definition and callable. |
| `SecretBroker` methods | Secret registration, policy-gated use/rotation/revocation, encryption, and audit. | Repository, vault/key manager, typed request, host-created context, and operation callback/material. |
| `AgentSecurityOrchestrator.process(...)` | Prompt analysis followed by dispatch to one of the three gateways above. | A typed request, configured gateways, and trusted context (explicit or configured default). |

The first three are direct service entry points. They do not create an agent or infer trustworthy identity from user text. `process` is the unified interface when the application wants ASO to select the gateway by request type. `create_agent(...)` creates an agent but does not attach unguarded tools.

memory invokes the registered adapter, tools invoke the registered callable, and secret use invokes the supplied callback with temporary material. Developers still configure the resource connection, tool implementation, permissions, identity context and (for secrets) a key manager. ASO cannot safely infer those from an agent request.

## AgentSecurityOrchestrator

```python
AgentSecurityOrchestrator(
    framework, llm, prompt_template, M_Definition, T_Definition, S_Definition,
    database_path="aso.db", *, prompt_analyser=None, memory_access_layer=None,
    tool_guard=None, secret_broker=None, secret_context=None, tool_context=None,
)
```

| Argument | Meaning |
| --- | --- |
| `framework` | Converted to `Framework`. Values: `LANGCHAIN`, `CREWAI`, `AUTOGEN_MICROSOFT`, `GOOGLE_AGENT`, `OPENAI_SDK`, `LLAMAINDEX`, `PYDANTIC_AI`. The corresponding integration package is needed when calling `create_agent`. |
| `llm` | Required non-empty identifier retained on the orchestrator. It is not a model client; `create_agent` gets its model via `model_name`. |
| `prompt_template` | Required base instruction; combined with agent description by `create_agent`. |
| `M_Definition` | Legacy memory-context fallback. Must be a trusted `SecurityContext` if memory `process` is called without explicit context. |
| `T_Definition` | Legacy compatibility argument. Current tool dispatch uses `tool_guard` and `ToolSecurityContext`. |
| `S_Definition` | Legacy compatibility argument. Current secret dispatch uses `secret_broker` and `SecretSecurityContext`. |
| `database_path` | SQLite file for agent and decision metadata; `":memory:"` is useful in tests. Never store secret material here. |
| `prompt_analyser` | Object implementing `analyse(text)`. If omitted, creates `PromptAnalyser` using the Hugging Face prompt pipeline. |
| `memory_access_layer` | Memory gateway. Requests are denied when it is absent. |
| `tool_guard` | `ToolGuard` instance. Requests are denied when absent. |
| `secret_broker` | `SecretBroker` instance. Requests are denied when absent. |
| `secret_context` | Host-created default `SecretSecurityContext` for secret requests. |
| `tool_context` | Host-created default `ToolSecurityContext` for tool requests. |

The three positional definition arguments are currently required even when unused; pass `None` for unused legacy slots. The actual gateways are the keyword arguments above.

`process(request, context=None, *, secret_callback=None, secret_material=None)` accepts `MemoryRequest`, `ToolRequest`, or `SecretAccessRequest`. `context` is authenticated per-request context; if omitted, the configured default is used. Secret reads require an application-owned callback. Secret writes/updates require `SecretMaterial`, cleared on denied/error paths. The result is `OrchestrationResult(request_id, component, decision, data, reason_codes)`.

| `process` argument | Required content and behavior |
| --- | --- |
| `request` | One of the three typed request objects below. It must have a non-empty `request_id`; the request itself is first serialized and sent through prompt analysis. |
| `context` | Host-authenticated context matching the request: `SecurityContext` for memory, `ToolSecurityContext` for tools, or `SecretSecurityContext` for secrets. `None` selects the configured fallback. A mismatch denies dispatch. |
| `secret_callback` | Callable accepting one temporary `memoryview`. Used only for secret `read`; design it to perform the necessary operation and return a minimal derived result, never the plaintext bytes. |
| `secret_material` | `SecretMaterial` for secret `write`/`update` (the broker rotates the stored value). It is cleared on guarded failure paths. Do not reuse it after passing it in. |

For memory and tool requests, `process` calls `memory_access_layer.execute(request, context)` and `tool_guard.execute(request)`. For secrets, it calls `secret_broker.execute_with_secret`, `rotate`, or `revoke`, depending on `request.operation`. Current `process` supports secret operations `read`, `write`, `update`, and `delete`; direct broker registration is a separate setup call. Prompt analysis must return `ALLOW` before any of those calls happen.

`create_agent(agent_name, model_name, developer_name, description)` creates an agent with an empty tools list. Tools must be registered and routed through the guarded tool workflow. Close the SQLite connection with `close()` or a `with` block.

## PromptAnalyser

```python
PromptAnalyser(llm=None, max_prompt_chars=32_000)
```

| Argument | Meaning |
| --- | --- |
| `llm` | Object with `invoke(prompt)`. Its response must contain JSON with `decision` (`ALLOW`, `DENY`, or `QUARANTINE`), optional numeric `risk_score`, and optional `reason`. Inject a tested security model for production. |
| `max_prompt_chars` | Positive maximum size. Current code compares UTF-8 byte length with this value. |

`inspect(prompt)` returns extracted features; `analyse(prompt)` returns `PromptAnalysis(prompt, features, decision)`; `decision(prompt)` returns only the `GuardDecision`. Empty or over-limit input raises `ValueError`; inspection/model failures become `QUARANTINE`.

Without an injected model, it creates a Hugging Face text-generation pipeline using `PROMPT_GUARD_LLM_MODEL` or `gpt2`. This base model is not a purpose-trained security classifier and should not be assumed to produce policy JSON. `LangChainPromptAnalyser.from_environment(provider, model_name, max_prompt_chars)` supports OpenAI, Google, Hugging Face, and Ollama, requiring matching optional packages and credentials. Provider defaults and actual supported model behavior should be verified for your deployment.


## Memory gateway call and payload

The public operation is `GuardedMemoryAccessLayer.execute(request, context) -> AccessResult`. It owns the complete guarded flow for one memory operation. Register each backing adapter once; then pass the typed request and trusted context per call:

```python
from aso import (
    GuardedMemoryAccessLayer, MemoryRequest, Operation, SecurityContext,
    Adapter, StoreConfig, StoreRegistry,
)


registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="relational",
    provider="sqlite",
    adapter=SQLITE(database_path="agent_memory.db"),
    memory_types=frozenset({"profile"}),
    capabilities=frozenset({"read", "write", "update", "delete"}),
))
memory = GuardedMemoryAccessLayer(registry)

# Create this context from authenticated application state, never from the agent.
context = SecurityContext(
    agent_id="agent-42",
    tenant_id="tenant-7",
    allowed_stores=frozenset({"agent-profile"}),
    permissions=frozenset({"read", "write"}),
    session_id="session-2026-04",
)
request = MemoryRequest(
    agent_id="agent-42",
    operation=Operation.WRITE,
    store_id="agent-profile",
    payload={"preference": "concise answers"},
    memory_type="profile",
    metadata={"memory_id": "answer-style"},
)
result = memory.execute(request, context)
if result.decision.value == "ALLOW":
    print("memory operation completed", result.operation_id)
else:
    print("memory operation blocked", result.reason_codes)
```
available Adapters :

- Weaviate
- Milvus
- Chroma
- FAISS
- PostgreSQL
- Oracle
- SQL Server
- MariaDB
- CouchDB
- Firestore
- Valkey
- Memcached
- Neo4j
- Neptune
- ArangoDB
- TigerGraph
- LangGraph
- Solr
- OpenSearch
- Google Cloud Storage
- Azure Blob Storage
- JSON
- YAML
- CSV
- TXT
- Local files
- Qdrant
- Pinecone
- S3
- Redis
- MongoDB
- DynamoDB
- Elasticsearch
- SQLite

`execute` arguments:

| Argument | Required content |
| --- | --- |
| `request` | `MemoryRequest`. `agent_id` must equal the context identity; `store_id` must be registered and in `allowed_stores`; `operation` must be enabled both in context permissions and store capabilities. |
| `context` | Trusted `SecurityContext`; must contain the authenticated `agent_id`, non-empty `tenant_id` and `session_id`, the allowed store IDs, and permitted operations. Its `policies` mapping is optional metadata; current gateway authorization is primarily based on identity, scopes, and permissions. |

`MemoryRequest` fields:

| Field | What to put in it |
| --- | --- |
| `agent_id` | Authenticated agent identifier; must match `context.agent_id`. |
| `operation` | `read`, `search`, `write`, `update`, or `delete`. `search` is treated as a read for MemoryGuard policy. |
| `store_id` | Logical registered store ID, not a connection string or credential. |
| `request_id` | Correlation ID; generated when omitted. Supply one if you need to correlate logs across services. |
| `payload` | New memory content for `write`/`update`; any structured value is serialized for inspection. |
| `query` | Search/read query text when the adapter supports it. |
| `limit` | Integer 1 through 1000; a bound for adapters that use result limits. |
| `filters` | Structured filter mapping for the adapter. |
| `memory_type` | Policy category such as `profile` or `conversation`; must be in `StoreConfig.memory_types` (or `*`). |
| `metadata` | Non-secret adapter metadata. `metadata["memory_id"]` selects a specific item in the current gateway implementation. Do not put credentials here. |

`StoreConfig` fields are `store_id` (logical key), `store_type` (category label), `provider` (adapter provider label), `adapter` (object exposing operation methods), `memory_types` (allowed categories), `capabilities` (allowed operations), `enabled` (gate switch), and optional non-secret `metadata`. `StoreRegistry.register(config)` makes this store available. `AccessResult` returns request ID, decision, data only when allowed, reason codes, and an optional operation ID.

## Adapter credentials and secret-backed credentials

ASO separates credential ownership from agent-controlled request data.

For memory adapters, credentials are configured in the application before the adapter is registered in the `StoreRegistry`. The adapter object is responsible for connecting to its provider, and the app owns the environment or secret resolution. `ProviderCredentials` is the application-facing contract for this step:

```python
import os
from MemoryGuard.config import ProviderCredentials, SecurityContext, MemoryRequest, Operation

credentials = ProviderCredentials(
    provider="qdrant",
    endpoint="https://example-qdrant.internal",
    api_key_env="QDRANT_API_KEY",
    require_tls=True,
    timeout_seconds=20,
)

os.environ["QDRANT_API_KEY"] = "prod-key-from-kms-or-secret-manager"

resolved = credentials.resolve()
print(resolved["api_key"])  # application-managed secret, not agent-provided payload data
```

The memory backend then uses those resolved values when constructing its SDK client. `MemoryGuard.memory_access_layer._managed_provider_config()` specifically strips `credentials` out of the adapter config and resolves them into the real provider connection parameters. This is important: the adapter config is not supposed to carry agent-supplied or request-derived secrets in `request.metadata`; credentials live in the host environment, a secret manager, or a KMS-backed application object.

A typical memory registration looks like this:

```python
from MemoryGuard.config import StoreConfig
from MemoryGuard.memory_access_layer import QdrantBackend

backend = QdrantBackend(
    collection="agent_memory",
    url="https://example-qdrant.internal",
    api_key=os.environ["QDRANT_API_KEY"],
)

registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="vector",
    provider="qdrant",
    adapter=backend,
    memory_types=frozenset({"profile", "conversation"}),
    capabilities=frozenset({"read", "write", "update", "delete", "search"}),
    enabled=True,
))
```

Notice the flow clearly:

1. The host creates the adapter and resolves credentials.
2. The host registers the adapter in `StoreRegistry`.
3. `AgentSecurityOrchestrator.process()` receives a request and a trusted context.
4. The orchestrator calls `memory_access_layer.execute(request, context)`.
5. The memory gateway checks authorization and only then invokes the adapter method.

`AgentSecurityOrchestrator.process` does not inject adapter credentials from the request. It does not read credentials from `MemoryRequest.metadata`, `ToolRequest.arguments`, or `SecretAccessRequest`; that would be unsafe and would let the untrusted request influence provider access. The trusted identity/context is the only thing it validates before dispatch.

For secret material, the flow is different but equally strict. `SecretBroker` is the secret gateway, and it handles secret registration and usage through `SecretMaterial` and a `SecretVault`/key manager. `SecretMaterial.from_value(...)` creates runtime-only plaintext, which the broker immediately clears or encrypts and never persists in the request object. A `SecretAccessRequest` carries only an identifier, tenant, requester, tool, and purpose; it does not carry the secret value.

```python
from SecretGuard.config import SecretAccessRequest, SecretMaterial, SecretSecurityContext, SecretType

secret_material = SecretMaterial.from_value("sk-prod-123")
# register in trusted app setup, never as agent input
# broker stores encrypted secret and keeps plaintext only in-memory during the operation
```

So the credential flow is:

- Memory adapters: app-owned credentials in adapter construction or environment resolution.
- Secret broker: `SecretMaterial` is passed only in trusted host code during registration/rotation; the request contains only metadata.
- `AgentSecurityOrchestrator.process`: validates prompt + trusted context, then dispatches to the proper gateway. It never pulls provider credentials from the request and never turns the agent into a secret owner.

## ToolGuard

```python
ToolGuard(registry=None, audit=None, llm_analyser=None)
```

| Argument | Meaning |
| --- | --- |
| `registry` | `ToolRegistry` mapping developer-owned `ToolDefinition` objects to Python callables. Unknown tools are denied. |
| `audit` | `ToolAuditStore` for encrypted audit data. The default uses `tool_guard.db` and requires `TOOL_GUARD_KEY`; inject a configured audit store for tests and production. |
| `llm_analyser` | Optional callable `(serialized_payload, features) -> mapping` for pre-request and post-output analysis. Missing, malformed, or failed analysis fails to review/quarantine. No LLM is enabled by default. |

`ToolDefinition` declares ID, name, description, purpose, allowed operations/resources, schemas, and risk metadata. `ToolRequest` carries request/agent/session/task IDs, tool ID, purpose, reason, arguments, and optional task/history context. Build identity from trusted host state. `execute(request)` returns `ToolResult`; the implementation runs only after pre-check allows it, and its output is withheld if post-check rejects it. The current schema check validates only top-level JSON-like types, not full JSON Schema; validate arguments inside the tool too.

### Tool execution call and payload

The public operation is `ToolGuard.execute(request: ToolRequest) -> ToolResult`. Before executing anything, register a `ToolDefinition` and callable together:

```python
registry = ToolRegistry()
registry.register(
    ToolDefinition(
        tool_id="ticket_lookup",
        name="Ticket lookup",
        description="Read a ticket status.",
        purpose="Look up a ticket requested by the current user.",
        operations=frozenset({"lookup"}),
        allowed_resources=frozenset({"T-100"}),
        output_schema={"type": "object"},
    ),
    lookup_ticket,
)
guard = ToolGuard(registry=registry, audit=configured_audit_store)
request = ToolRequest(
    request_id="req-100",
    agent_id="agent-42",
    session_id="session-2026-04",
    task_id="task-11",
    tool_id="ticket_lookup",
    purpose="Read the status of ticket T-100.",
    reason="The user asked for the ticket status.",
    arguments={"operation": "lookup", "ticket_id": "T-100"},
)
result = guard.execute(request)
```

`execute` takes one argument:

| Argument | Required content |
| --- | --- |
| `request` | A `ToolRequest`. `tool_id` selects the registered definition/callable. Required IDs must be non-empty. Explain the purpose and reason, and provide only the operation arguments the callable needs. |

`ToolRequest` fields:

| Field | What to put in it |
| --- | --- |
| `request_id` | Unique correlation ID for this invocation. |
| `agent_id`, `session_id`, `task_id` | Authenticated agent/session and current task IDs. When called through `process`, agent/session/tool must match its trusted `ToolSecurityContext`. Direct `ToolGuard.execute` does not accept a context object, so the application must authenticate and authorize identity before calling it. |
| `tool_id` | Exact ID registered in `ToolRegistry`. |
| `purpose`, `reason` | Human-readable, specific why the tool and this operation are needed. Empty values cause review. |
| `arguments` | Mapping passed to the callable as keyword arguments (unknown keys are filtered unless the callable accepts `**kwargs`). Include `operation` when the definition lists operations. |
| `task_context` | Optional bounded task background relevant to this invocation. |
| `previous_tool_context` | Optional sequence summarizing prior calls; chains longer than 50 are reviewed. |
| `timestamp` | Optional caller timestamp; if omitted, guard decisions use their own current timestamp. |

`ToolDefinition` fields and contents:

| Field | What to put in it |
| --- | --- |
| `tool_id`, `name`, `description`, `purpose` | Stable ID, human-readable name, what it does, and its intended security-approved use. The first four are required and non-empty. |
| `input_schema`, `output_schema` | Mapping describing input/output shape. Current enforcement checks only output's top-level `type`; validate inputs and full schemas in the implementation. |
| `expected_output` | Short description of the expected result used as context for output review. |
| `operations` | Allowed operation strings, compared to `request.arguments["operation"]` when set. |
| `side_effects`, `required_capabilities` | Descriptive declarations of effects and capabilities; do not assume these are independently enforced currently. |
| `allowed_resources` | Resource identifiers the request arguments must intersect; use narrow IDs, not broad wildcards. |
| `forbidden_operations` | Values that must never appear among request argument values. |
| `sensitivity`, `risk_characteristics`, `execution_constraints` | Additional policy/context metadata. Enforce critical constraints inside the callable until the guard explicitly supports them. |

The definition's `operations`, `forbidden_operations`, and `allowed_resources` take part in deterministic pre-checks. The registered callable is run inside `execute`, then output inspection runs before returning `ToolResult`; a denied/quarantined result has no data. The default audit store needs `TOOL_GUARD_KEY`, so supply a configured `ToolAuditStore` in production.

## SecretGuard

`SecretGuard()` has no constructor arguments. `evaluate_store(definition, permissions)` checks registration/storage policy. `evaluate_access(definition, permissions, request, status)` checks active status, type, operation, destination, exposure, and purpose, returning a decision and reason codes. It does not store or return plaintext.

The normal path uses `SecretBroker(repository, vault, permissions=None, guard=None)`. `SecretVault(repository, key_manager)` performs encrypted storage and bounded secret use. Production must inject a KMS/HSM-backed `KeyManager`; `LocalDevelopmentKeyManager` is development-only. `SecretMaterial.from_value(...)` is trusted registration/rotation input and is cleared by broker paths. `SecretAccessRequest` describes the operation without secret bytes. `SecretSecurityContext` is host-created and binds tenant, requester, agent, session, and authorized tool IDs.

Reads use `SecretBroker.execute_with_secret(request, context, callback)`. The callback receives a temporary `memoryview`; return only the minimum derived result, never the bytes. The broker checks trusted context and policy before callback and audits the event. Never log callback input, `SecretMaterial.value`, API keys, or environment values. The local key manager requires `SECRETGUARD_DEV_KEK_B64`; never use it for production.

### SecretBroker calls and payloads

`SecretBroker(repository, vault, permissions=None, guard=None)` composes the secret application. `repository` is a `SecretRepository` for metadata/ciphertext/audit persistence. `vault` is a `SecretVault` built with that repository and a `KeyManager`. `permissions` is a default deny-by-default `SecretPermissions` policy for secrets without a stored per-secret policy; `guard` is a `SecretGuard` policy evaluator. Normal registered secrets use their stored definition and permissions.

| Broker method | Arguments and contents |
| --- | --- |
| `register_secret(definition, material, tenant_id, permissions)` | `definition`: metadata/policy (`name`, `secret_type`, `source`, permitted `operations` and `destinations`, `allowed`, `exposed`, optional `secret_id`); `material`: trusted `SecretMaterial` bytes, cleared by the method; `tenant_id`: authenticated tenant; `permissions`: explicit policy. Returns `(secret_id, version)`. |
| `execute_with_secret(request, context, callback)` | `request`: `SecretAccessRequest` for the target/operation; `context`: host-authenticated `SecretSecurityContext`; `callback`: callable receiving a temporary `memoryview` to perform bounded use. Returns callback result, not the secret itself. |
| `rotate(request, context, material)` | Existing authorized secret request/context plus new `SecretMaterial`. Stores a new version and clears the material. |
| `revoke(request, context, operation="revoke")` | Authorized request/context; `operation` is `revoke` or `delete`. Current implementation marks the secret revoked for either value; it does not physically delete the row here. |

`SecretAccessRequest` fields:

| Field | What to put in it |
| --- | --- |
| `request_id` | Unique audit/correlation ID. |
| `secret_id` | ID returned by `register_secret`; never use the secret value as an identifier. |
| `tenant_id`, `requester`, `agent_id`, `session_id` | Authenticated identity values; each must match the host-created context. |
| `tool_id` | Calling tool ID; must be in `context.authorized_tools`. |
| `purpose` | Specific business reason for the secret operation; required for access. |
| `operation` | Policy operation such as `read`, `write`, `update`, `delete`, or `revoke`, as configured in definition/permissions. |
| `destination` | Approved destination/use label checked against both definition and permissions. |
| `version` | Optional explicit secret version; `None` selects the current active version. |

`SecretSecurityContext` fields are `tenant_id`, `requester`, `agent_id`, `session_id`, and `authorized_tools`. Create it after application authentication and do not accept it from the agent. `SecretPermissions` fields are `unregistered` (whether unregistered requests can be quarantined), `allowed_use`, `allowed_type` (set of `SecretType` values), `allowed_destination`, `allowed_operations`, and `allowed_exposed` (explicit opt-in to plaintext reaching the authorized callback). Keep exposure disabled unless the specific flow requires it.

The `process` interface maps secret `read` to `execute_with_secret`, `write`/`update` to `rotate`, and `delete` to `revoke(operation="delete")`. It does not expose `register_secret` through an agent request; register secrets in trusted application setup. Direct broker calls should likewise be made by trusted host code, not by giving the agent a broker or vault handle.

## Alerting integration

ASO enforces fail-closed policies and returns a `QUARANTINE` decision when the request or result looks suspicious. The library does not ship a built-in mailer or transport layer. The host application should hook its own escalation path so developers are alerted when a quarantine occurs.

### SMTP email escalation

```python
import smtplib
from email.message import EmailMessage


def send_smtp_alert(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "aso-alerts@example.com"
    msg["To"] = "security@example.com"
    msg.set_content(body)

    with smtplib.SMTP("smtp.example.com", 587) as smtp:
        smtp.starttls()
        smtp.login("smtp-user", "smtp-password")
        smtp.send_message(msg)


def maybe_alert(result) -> None:
    if getattr(result, "decision", "") == "QUARANTINE":
        send_smtp_alert(
            "ASO quarantine notice",
            f"decision={result.decision}\nreasons={getattr(result, 'reason_codes', ())}",
        )
```

Use this pattern when you want an email alert to go to the security team or the app owners. Keep the SMTP server and credentials in the host configuration, not inside the request.

### Slack escalation

```python
import json
import urllib.request


def send_slack_alert(webhook_url: str, result) -> None:
    payload = {
        "text": (
            "ASO quarantine alert\n"
            f"decision={result.decision}\n"
            f"reasons={getattr(result, 'reason_codes', ())}"
        )
    }
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()
```

This is suitable for a team channel or on-call room. It should be triggered only after ASO produces a quarantined decision or fails closed.

### Webhook-based escalation

```python
import json
import urllib.request


def send_webhook_alert(webhook_url: str, result) -> None:
    payload = {
        "event": "aso_quarantine",
        "request_id": getattr(result, "request_id", "unknown"),
        "decision": getattr(result, "decision", "UNKNOWN"),
        "reason_codes": list(getattr(result, "reason_codes", ())),
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()
```

Webhook-based escalation is useful for SIEM systems, incident platforms or a custom internal service that converts quarantine events into ticketing, paging or Slack/SMS notifications.

### Recommended pattern

```python
def handle_result(result) -> None:
    if getattr(result, "decision", "") == "QUARANTINE":
        send_slack_alert("https://hooks.slack.com/services/your/webhook", result)
        send_webhook_alert("https://internal.example.com/aso/alerts", result)
```

Use the result object from the guard or the orchestrator as the source of truth for escalation. Do not build escalation logic from untrusted agent input. The host should log, page, and retain the event securely.

## Operational Checklist

- Authenticate identities in the host and create trusted contexts there.
- Register only necessary tools and resources; put guards directly in front of actual operations.
- Test benign, adversarial, malformed, and unavailable-model cases.
- Configure timeouts, network restrictions, and application-level validation around providers.
- Keep audit databases and encryption keys outside agent-visible paths.
- Use KMS/HSM for production secrets; the bundled local key manager is development-only.
- Treat `ALLOW` as the result of implemented checks, not proof of safety.

