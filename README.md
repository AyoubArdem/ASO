<div align="center">

# AgentSecurityOrchestrator library(ASO)

### A Security Orchestration Framework for AI Agents

**Inspect. Decide. Authorize. Protect.**

A modular security framework designed to inspect AI-agent prompts, coordinate security decisions, govern memory access, control tool execution and protect sensitive secrets throughout an agent's execution lifecycle.

[Architecture](#architecture) ·
[Security Pipeline](#security-pipeline) ·
[Core Components](#core-components) ·
[Decision Engine](#decision-engine) ·
[Security Model](#security-model) ·
[Roadmap](#roadmap) ·
[ASO Tutorial](docs/aso_tutorial.md) 

</div>

---

## 1. Overview

**AgentSecurityOrchestrator (ASO)** is a modular security orchestration library designed to introduce a dedicated security layer between AI agents and the resources they interact with.

Modern AI agents can interpret natural-language instructions, access persistent memory, invoke external tools, retrieve sensitive credentials and execute multi-step tasks.

These capabilities introduce security risks that cannot be addressed reliably by examining the initial prompt alone.

An apparently legitimate request may lead an agent to:

- Follow malicious instructions embedded in user input or retrieved content.
- Access memory containing information unrelated to its current task.
- Invoke tools for unauthorized purposes.
- Send sensitive information to an unauthorized destination.
- Retrieve or expose secrets unnecessarily.
- Continue execution after a security violation has been detected.

ASO addresses these challenges through a modular architecture in which specialized security applications inspect different aspects of an agent's behavior, while a central Decision Engine coordinates security decisions.

Rather than treating agent security as a single classification problem, ASO separates security inspection, decision-making, intent analysis, resource authorization and execution control.

### Core principle

> An AI agent should not be allowed to access a protected resource or perform a sensitive operation merely because a prompt requests it. The operation must pass the applicable security controls before execution.

ASO is designed to make security decisions explicit, inspectable, and enforceable at defined points in the agent lifecycle.

### Public API flow

The actual end-user flow is simple: instantiate the orchestrator, build a trusted host context, then call `AgentSecurityOrchestrator.process(...)` with a typed request.

The example below is a single minimal script that exercises the three public gateways together and includes a host-side developer alert helper for quarantine decisions. ASO returns the decision and reason codes; the email/Slack notification itself is application-owned, not part of the library core.

```python
import base64
import os

from aso import (
    AgentSecurityOrchestrator,
    Framework,
    GuardedMemoryAccessLayer,
    KeyManager,
    LocalDevelopmentKeyManager,
    MemoryRequest,
    Operation,
    SecretAccessRequest,
    SecretBroker,
    SecretDefinition,
    SecretMaterial,
    SecretPermissions,
    SecretRepository,
    SecretSecurityContext,
    SecretType,
    SecretVault,
    SecurityContext,
    StoreConfig,
    StoreRegistry,
    ToolDefinition,
    ToolGuard,
    ToolRegistry,
    ToolRequest,
    ToolSecurityContext,
)


def send_email_alert(subject: str, body: str) -> None:
    # Replace this with SMTP, SendGrid, SES, or your internal mail service.
    print(f"[EMAIL ALERT] {subject}\n{body}")


def alert_if_quarantined(result, component: str) -> None:
    if getattr(result, "decision", "") == "QUARANTINE":
        send_email_alert(
            f"ASO quarantine alert: {component}",
            f"component={component}\nreason_codes={getattr(result, 'reason_codes', ())}",
        )


# --- memory setup ---
os.environ.setdefault("SECRETGUARD_DEV_KEK_B64", base64.b64encode(b"0123456789abcdef0123456789abcdef").decode())

registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="sqlite",
    provider="sqlite",
    adapter=SQLITE(database_path="agent_memory.db"),
    memory_types=frozenset({"profile"}),
    capabilities=frozenset({"read", "write", "update", "delete"}),
))

memory_context = SecurityContext(
    agent_id="agent-42",
    tenant_id="tenant-7",
    allowed_stores=frozenset({"agent-profile"}),
    permissions=frozenset({"read", "write"}),
    session_id="session-100",
)

# --- tool setup ---
def lookup_ticket(ticket_id: str) -> dict:
    return {"ticket_id": ticket_id, "status": "open"}


tool_registry = ToolRegistry()
tool_registry.register(
    ToolDefinition(
        tool_id="lookup_ticket",
        name="Lookup ticket",
        description="Read a ticket status by ID.",
        purpose="Check the status of a ticket requested by the user.",
        operations=frozenset({"lookup"}),
        allowed_resources=frozenset({"T-100"}),
        output_schema={"type": "object"},
    ),
    lookup_ticket,
)

tool_context = ToolSecurityContext(
    agent_id="agent-42",
    session_id="session-100",
    authorized_tools=frozenset({"lookup_ticket"}),
)

# --- secret setup ---
secret_repo = SecretRepository("secret_guard.db")
secret_vault = SecretVault(secret_repo, LocalDevelopmentKeyManager())
secret_broker = SecretBroker(secret_repo, secret_vault, permissions=SecretPermissions())

secret_permissions = SecretPermissions(
    allowed_use=True,
    allowed_type=frozenset({SecretType.GOOGLE_API_KEY}),
    allowed_destination=frozenset({"external-api"}),
    allowed_operations=frozenset({"read"}),
    allowed_exposed=False,
)

secret_id, _ = secret_broker.register_secret(
    SecretDefinition(
        name="Example Google API key",
        secret_type=SecretType.GOOGLE_API_KEY,
        source="environment",
        operations=frozenset({"read"}),
        destinations=frozenset({"external-api"}),
        allowed=True,
        exposed=False,
    ),
    SecretMaterial.from_value("AIza-test-example"),
    tenant_id="tenant-7",
    permissions=secret_permissions,
)

secret_context = SecretSecurityContext(
    tenant_id="tenant-7",
    requester="service-account",
    agent_id="agent-42",
    session_id="session-100",
    authorized_tools=frozenset({"lookup_ticket"}),
)

# --- orchestrator ---
orchestrator = AgentSecurityOrchestrator(
    framework=Framework.LANGCHAIN,
    llm="security-model",
    prompt_template="Follow the ASO security policy.",
    M_Definition=memory_context,
    T_Definition=None,
    S_Definition=None,
    memory_access_layer=GuardedMemoryAccessLayer(registry),
    tool_guard=ToolGuard(registry=tool_registry, trusted_context=tool_context),
    secret_broker=secret_broker,
    tool_context=tool_context,
    secret_context=secret_context,
)

# --- memory request ---
memory_result = orchestrator.process(
    MemoryRequest(
        agent_id="agent-42",
        operation=Operation.WRITE,
        store_id="agent-profile",
        payload={"preference": "concise answers"},
        memory_type="profile",
        metadata={"memory_id": "answer-style"},
    ),
    context=memory_context,
)
print("memory:", memory_result.decision, memory_result.reason_codes)
alert_if_quarantined(memory_result, "memory")

# --- tool request ---
tool_result = orchestrator.process(
    ToolRequest(
        request_id="req-tool-1",
        agent_id="agent-42",
        session_id="session-100",
        task_id="task-1",
        tool_id="lookup_ticket",
        purpose="Read the status of ticket T-100.",
        reason="The user asked for the status of a valid ticket.",
        arguments={"operation": "lookup", "ticket_id": "T-100"},
    ),
    context=tool_context,
)
print("tool:", tool_result.decision, tool_result.reason_codes)
alert_if_quarantined(tool_result, "tool")

# --- secret request ---
secret_result = orchestrator.process(
    SecretAccessRequest(
        request_id="req-secret-1",
        secret_id=secret_id,
        tenant_id="tenant-7",
        requester="service-account",
        agent_id="agent-42",
        session_id="session-100",
        tool_id="lookup_ticket",
        purpose="Call the external API for the user request.",
        operation="read",
        destination="external-api",
    ),
    context=secret_context,
    secret_callback=lambda view: "token-ok",
)
print("secret:", secret_result.decision, secret_result.reason_codes)
alert_if_quarantined(secret_result, "secret")
```

This is the supported model for library users:

- app-owned credentials are configured before dispatch
- trusted identity context is created by the host
- agent-controlled request data is never treated as proof of authorization
- `process(...)` is the unified entry point for memory, tool, and secret requests
- when a guard decides `QUARANTINE`, the app should notify the developer through its own email or incident system

### Legacy slots stay explicit: `T_Definition=None` and `S_Definition=None`

In the current public API, the orchestrator still accepts the legacy positional slots for memory/tool/secret definitions, but the actual authorization path is supplied through the concrete gateways:

```python
orchestrator = AgentSecurityOrchestrator(
    framework=Framework.LANGCHAIN,
    llm="security-model",
    prompt_template="Follow the ASO security policy.",
    M_Definition=memory_context,
    T_Definition=None,   # legacy placeholder; tool auth is handled by ToolGuard
    S_Definition=None,   # legacy placeholder; secret auth is handled by SecretBroker
    memory_access_layer=GuardedMemoryAccessLayer(registry),
    tool_guard=ToolGuard(registry=tool_registry, trusted_context=tool_context),
    secret_broker=secret_broker,
    tool_context=tool_context,
    secret_context=secret_context,
)
```

This keeps compatibility with earlier ASO construction patterns without forcing tool or secret policy to be passed as a generic definition object. The real authorization happens in the host-managed gateways, not in agent-provided request fields.

### Adapter credentials stay in the host

Memory adapters are created and configured by the application before being registered. Provider secrets are resolved from environment variables, secret managers, or KMS-backed configuration. They are not read from `MemoryRequest.metadata`, `ToolRequest.arguments`, or the agent prompt:

```python
from MemoryGuard.config import ProviderCredentials

credentials = ProviderCredentials(
    provider="qdrant",
    endpoint="https://example-qdrant.internal",
    api_key_env="QDRANT_API_KEY",
    require_tls=True,
    timeout_seconds=20,
)

resolved = credentials.resolve()
print(resolved["api_key"])  # app-managed secret, not agent-controlled input
```

This is the intended design for ASO: the host owns the credentials, the adapter owns the network connection, and `AgentSecurityOrchestrator.process(...)` validates the trusted context before dispatching to the correct guard.

---

## 2. Project Objectives

ASO aims to provide a reusable security foundation for developers building AI agents.

Its primary objectives are:

1. **Prompt Inspection**  
   Analyze incoming prompts before they enter the agent's normal execution flow.

2. **Centralized Decision Orchestration**  
   Coordinate security decisions and determine whether processing should stop, be quarantined or continue.

3. **Intent-Aware Authorization**  
   Introduce an intermediate analysis stage to identify what the agent intends to do with an accepted prompt.

4. **Memory Protection**  
   Inspect and govern memory read and write operations.

5. **Tool Governance**  
   Evaluate why an agent wants to invoke a tool and inspect the results returned by that tool.

6. **Secret Protection**  
   Govern access to sensitive credentials and prevent unauthorized exposure.

7. **Modular Security Applications**  
   Allow security capabilities to evolve independently while participating in a shared orchestration workflow.

8. **Developer-Controlled Policies**  
   Allow application developers to define legitimate resources, permitted operations, trusted destinations, and application-specific security requirements.

---

## 3. Architecture

ASO follows a layered architecture.

At a high level, the system consists of an initial prompt inspection stage, a central Decision Engine, an intent-analysis stage and specialized security applications.

### High-level architecture

```text
                    USER INPUT
                         |
                         v
                +------------------+
                |   PromptGuard    |
                |                  |
                | Prompt Inspection|
                +------------------+
                         |
                         v
                +------------------+
                |  Decision Engine |
                |                  |
                | STOP / QUARANTINE|
                |      / ACCEPT    |
                +------------------+
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
           STOP      QUARANTINE    ACCEPT
             |           |           |
             v           v           v
        Terminate     Alert the   Intent Analysis
        processing    developer        |
                                     v
                            +------------------+
                            | Agent Intent and |
                            | Task Analysis    |
                            +------------------+
                                     |
                                     v
                            Determine required
                            resources/actions
                                     |
                 +-------------------+-------------------+
                 |                   |                   |
                 v                   v                   v
          +-------------+      +-------------+     +-------------+
          | MemoryGuard |      |  ToolGuard   |    | SecretGuard |
          +-------------+      +-------------+     +-------------+
                 |                   |                   |
                 v                   v                   v
          Memory access       Tool authorization    Secret access
          and inspection      and result analysis   and protection
                 |                   |                   |
                 +-------------------+-------------------+
                                     |
                                     v
                           Security decisions
                                     |
                                     v
                         Controlled agent execution
```

This diagram represents the logical architecture. The exact execution sequence depends on the operation requested by the agent and the policies configured by the developer.

### Architectural separation

ASO separates three important responsibilities:

| Layer | Responsibility |
|---|---|
| Security inspection | Analyze prompts, operations, resource requests, and relevant outputs. |
| Decision orchestration | Coordinate security decisions and determine whether execution can proceed. |
| Resource-specific guards | Enforce security requirements for memory, tools, and secrets. |

This separation prevents the initial prompt classifier from becoming the only security boundary protecting the entire agent.

---

## 4. Security Pipeline

The ASO execution pipeline begins before the agent processes a prompt normally.

### Stage 1: Prompt submission

A user submits a prompt or task.

The prompt is passed to `PromptGuard` for inspection.

```text
User
 |
 v
Prompt
 |
 v
PromptGuard
```

The inspection stage is responsible for evaluating the incoming prompt according to the configured prompt-security logic.

Its purpose is to identify suspicious or prohibited instructions before they proceed through the normal agent workflow.

Prompt inspection is an initial security control, not a guarantee that all malicious behavior will be detected.

### Stage 2: Decision Engine

The result produced by `PromptGuard` is evaluated by the central Decision Engine.

The current decision model contains three outcomes:

- `DENY`
- `QUARANTINE`
- `ACCEPT`

These outcomes control the next stage of processing.

#### DENY

When the prompt is classified as requiring a stop:

```text
Prompt
  |
  v
PromptGuard
  |
  v
DENY
  |
  v
Terminate processing
```

The prompt does not proceed through the normal agent execution pipeline.

The implementation should ensure that stopping execution also prevents downstream tools or protected resources from being invoked through the rejected request.

#### QUARANTINE

When the prompt requires quarantine:

```text
Prompt
  |
  v
PromptGuard
  |
  v
QUARANTINE
  |
  v
Notify developer
  |
  v
Hold for review or policy-defined handling
```

The purpose of quarantine is to prevent suspicious input from proceeding automatically.

A notification should contain the information necessary to investigate the event without unnecessarily exposing credentials or other sensitive data.

The precise quarantine storage, notification delivery, and release mechanisms depend on the configured implementation.

#### ACCEPT

When the prompt is accepted:

```text
Prompt
  |
  v
PromptGuard
  |
  v
ACCEPT
  |
  v
Intent Analysis
```

**ACCEPT means that the prompt may proceed to the next security stage. It does not grant unrestricted access to memory, tools, or secrets.**

This distinction is fundamental to the ASO architecture.

A prompt can be acceptable while a particular action requested or proposed during its execution remains unauthorized.

### Stage 3: Intent and task analysis

After an accepted prompt passes the initial decision stage, ASO introduces an AI-based analysis component.

Its purpose is to ask:

> What does the agent intend to do with this prompt or task?

The analysis identifies which resources or capabilities may be required.

For example:

| Identified requirement | Security application |
|---|---|
| Read information from persistent memory | `MemoryGuard` |
| Write information to persistent memory | `MemoryGuard` |
| Invoke an external or internal tool | `ToolGuard` |
| Access a protected API credential | `SecretGuard` |
| Perform a task requiring multiple protected resources | Relevant guards are evaluated independently |

The intent-analysis component helps route operations to the appropriate security applications.

However, its output is not itself authorization.

An AI-generated statement such as "I need this secret to complete the task" must not automatically grant access to that secret.

The corresponding guard must evaluate the actual requested operation against the applicable policies and contextual evidence.

### Stage 4: Resource-specific security evaluation

When the agent requests a protected operation, the appropriate guard evaluates it.

```text
Intent Analysis
      |
      v
Resource Request
      |
      v
Relevant Guard
      |
      v
Security Evaluation
      |
      v
Authorized Operation
      |
      v
Execution
```

If the operation is not authorized, the guard must prevent the protected operation from proceeding through the controlled execution path.

The central orchestration layer can then coordinate the result according to the framework's decision-handling rules.

---

## 5. Core Components

ASO is organized around specialized security applications.

Each application addresses a different attack surface.

### 5.1 PromptGuard

**Purpose:** Inspect incoming prompts before they enter the normal agent execution workflow.

PromptGuard is the first security application in the current pipeline.

Its responsibilities include:

- Inspecting incoming prompt content.
- Extracting security-relevant information.
- Identifying suspicious instructions according to its detection logic.
- Producing a result for the Decision Engine.
- Providing evidence that can support subsequent investigation.

Prompt inspection should consider more than individual suspicious keywords.

Depending on the implemented detectors, relevant signals may include instruction conflicts, attempts to override security boundaries, requests to expose sensitive information, and suspicious instructions embedded in otherwise legitimate content.

PromptGuard is not intended to replace MemoryGuard, ToolGuard, or SecretGuard.

A prompt that passes initial inspection can still lead to an unauthorized operation later.

**Pipeline position:**

```text
User Prompt
    |
    v
PromptGuard
    |
    v
Decision Engine
```

### 5.2 MemoryGuard

**Purpose:** Govern the agent's interactions with persistent memory.

AI agents may use vector databases, relational databases, document stores, caches, or other storage systems.

Memory access creates risks involving unauthorized retrieval, malicious stored instructions, inappropriate data retention, and disclosure of sensitive information.

MemoryGuard is designed to introduce security inspection before protected memory operations are performed.

Its intended responsibilities include:

- Inspecting memory read requests.
- Inspecting memory write requests.
- Evaluating whether the requested operation is authorized.
- Checking relevant metadata and contextual information.
- Applying policies before allowing access to the underlying memory system.
- Recording security-relevant operation metadata.
- Supporting different database technologies through an adapter-oriented access layer.

#### Memory access architecture

```text
             AI Agent
                 |
                 v
          Memory Request
                 |
                 v
          MemoryGuard
                 |
                 v
       Memory Access Layer
                 |
                 v
       Database-Specific Adapter
                 |
                 v
        Actual Memory Database
```

The intended architecture places a controlled access layer between the agent and the actual memory backend.

The agent should not be able to bypass this layer through an alternative connection path.

#### Read operations

A read request may be evaluated using information such as:

- Requesting agent and tool identity.
- Requested memory operation.
- Database or storage backend.
- Access scope.
- Relevant authorization metadata.
- Request context.
- Applicable memory-access policies.

After authorization, the access layer performs the read and returns the permitted result.

Returned content may still require inspection before it is provided to the agent.

#### Write operations

A write request may be evaluated using:

- Data classification.
- Data source.
- Intended memory destination.
- Requested retention or update operation.
- Authorization context.
- Applicable storage policies.

The system can reject or isolate writes that violate the configured policy.

This is particularly important when an agent attempts to store untrusted instructions or information that should not persist across sessions.

#### Database adapter strategy

MemoryGuard should separate security policy from database-specific implementation.

Conceptually:

```text
MemoryGuard
     |
     v
Memory Access Layer
     |
     +-- Vector Database Adapter
     |
     +-- Relational Database Adapter
     |
     +-- Document Database Adapter
     |
     +-- Cache Adapter
     |
     +-- Other Supported Adapters
```

Each adapter implements the operations supported by its underlying backend.

A new adapter should not require rewriting the core authorization logic.

Support for a particular database must be established through an actual adapter implementation and tests rather than assumed from the architecture alone.

### 5.3 ToolGuard

**Purpose:** Evaluate tool invocation requests and inspect tool execution results.

Tools give AI agents access to capabilities beyond text generation.

Depending on the application, these capabilities may include:

- HTTP requests.
- Database operations.
- File operations.
- Code execution.
- Search services.
- External APIs.
- Internal business systems.

ToolGuard is designed around three important questions:

1. Why does the agent want to invoke this tool?
2. Is the requested invocation authorized under the developer-defined tool configuration and current security policy?
3. What did the tool return after execution?

#### Tool invocation flow

```text
Agent
  |
  v
Tool Request
  |
  v
ToolGuard
  |
  +--> Analyze intended purpose
  |
  +--> Validate tool definition
  |
  +--> Evaluate requested operation
  |
  +--> Check destination and permissions
  |
  v
Security Decision
  |
  +--> Deny
  |
  +--> Quarantine
  |
  +--> Allow
           |
           v
      Tool Execution
           |
           v
      Tool Output
           |
           v
      Result Inspection
           |
           v
      Controlled Result
```

#### Developer-defined tool definitions

The developer defines the tools that the agent is allowed to use and the security constraints associated with them.

Depending on the implementation, a tool definition may specify:

- Tool identifier.
- Description.
- Permitted operations.
- Accepted arguments.
- Authorized destinations.
- Required permissions.
- Relevant execution constraints.

The agent's request should be evaluated against this definition.

The fact that a tool exists does not mean every invocation of that tool is authorized.

#### Why purpose analysis matters

Consider an agent that has access to a search tool.

A search request for publicly available documentation may be legitimate.

A request to transmit confidential database records to an unrelated external endpoint may not be.

ToolGuard should evaluate the actual operation and its context rather than trusting a natural-language explanation generated by the agent.

#### Tool result inspection

Security evaluation must not stop when a tool is authorized.

A tool may return:

- Sensitive credentials.
- Confidential records.
- Malicious instructions.
- Unexpected external content.
- Information outside the intended task scope.

ToolGuard therefore includes post-execution inspection in its intended workflow.

A tool's output should not automatically be trusted simply because the tool invocation was permitted.

### 5.4 SecretGuard

**Purpose:** Govern the registration, use, storage, and exposure of sensitive secrets.

Secrets commonly used by AI applications include:

- LLM provider API keys.
- Database credentials.
- Vector database credentials.
- Cloud access credentials.
- External search API keys.
- Messaging platform tokens.
- JWT signing secrets.
- OAuth client secrets.
- Encryption keys.
- Webhook secrets.

SecretGuard is designed to protect these resources throughout their lifecycle.

#### Secret registration

Developers should be able to define which secrets their application expects.

A secret definition can describe the secret type and the operations, sources, destinations, and exposure conditions permitted by policy.

The registry provides the metadata required to distinguish registered secrets from newly discovered or unrecognized values.

A detected secret is not automatically an authorized secret.

#### Secret access flow

```text
Agent / Tool
     |
     v
Secret Access Request
     |
     v
SecretGuard
     |
     +--> Identify requested secret
     |
     +--> Check registration
     |
     +--> Evaluate permissions
     |
     +--> Validate purpose and destination
     |
     +--> Apply global security policy
     |
     v
Secret Access Decision
     |
     v
SecretBroker
     |
     v
SecretVault
     |
     v
Controlled Secret Use
```

The exact placement of policy evaluation may be implemented across SecretGuard and SecretBroker, but the architecture must ensure that the actual secret-access path cannot bypass authorization.

#### SecretVault

SecretVault is the dedicated secure-storage component associated with SecretGuard.

Its intended responsibilities include:

- Persisting encrypted secret material.
- Keeping plaintext secrets out of persistent database records.
- Integrating with a key-management abstraction.
- Supporting controlled retrieval and rotation.
- Separating encrypted secret data from the keys required to decrypt it.
- Minimizing plaintext exposure during secret use.

A production-oriented implementation should use established cryptographic primitives and a suitable key-management system.

SecretGuard must also prevent secrets from leaking into application logs, audit events, exceptions, telemetry, or LLM context wherever the architecture can enforce that protection.

#### SecretBroker

SecretBroker provides a controlled gateway between application components and SecretVault.

Whenever possible, the application should perform an authorized operation using a secret without returning the raw secret to the AI agent.

For example:

```text
Less desirable:

LLM
 |
 v
Retrieve API key
 |
 v
Tool uses API key


Preferred:

LLM
 |
 v
Request an authorized operation
 |
 v
Tool / SecretBroker
 |
 v
SecretVault
 |
 v
Perform operation using the secret
 |
 v
Sanitized result
 |
 v
LLM
```

This design reduces the number of components that need access to plaintext credentials.

It does not eliminate every possible exposure risk, but it reduces unnecessary exposure by keeping the secret outside the normal language-model interaction whenever possible.

---

## 6. Decision Engine

The Decision Engine coordinates security outcomes across the initial prompt-inspection stage and the broader agent-security workflow.

Its purpose is to translate security results into explicit control-flow decisions.

### Initial decision model

The initial prompt pipeline uses:

```text
STOP
QUARANTINE
ACCEPT
```

These values describe the outcomes of the prompt-processing stage.

| Outcome | Meaning | Expected behavior |
|---|---|---|
| `DENY` | The prompt must not proceed through the normal pipeline. | Terminate the corresponding processing flow. |
| `QUARANTINE` | The prompt requires isolated handling or review. | Prevent normal continuation and notify the developer according to policy. |
| `ACCEPT` | The prompt may proceed to the next stage. | Run intent analysis and evaluate subsequent operations independently. |

These outcomes should not be confused with the resource-level decision model.

### Resource-level decisions

MemoryGuard, ToolGuard, and SecretGuard may use a common security decision model:

```python
class Decision(StrEnum):
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    ALLOW = "ALLOW"
```

Their meaning is:

- **ALLOW:** The requested operation may proceed within the authorized scope.
- **DENY:** The requested operation is not permitted.
- **QUARANTINE:** The operation or associated content requires isolated handling or additional review.

The initial prompt outcome and the resource-level decision are related but distinct.

An accepted prompt does not automatically produce an `ALLOW` decision for subsequent operations.

### Example

Suppose a user asks an agent to summarize information stored in memory.

```text
Prompt
  |
  v
PromptGuard
  |
  v
ACCEPT
  |
  v
Intent Analysis
  |
  v
Read Memory
  |
  v
MemoryGuard
  |
  v
ALLOW
  |
  v
Read authorized data
```

Now suppose the same agent attempts to retrieve a secret and send it to an unauthorized destination.

```text
Prompt
  |
  v
PromptGuard
  |
  v
ACCEPT
  |
  v
Intent Analysis
  |
  v
Secret Access Request
  |
  v
SecretGuard
  |
  v
DENY
  |
  v
Prevent the unauthorized operation
```

The prompt can be acceptable while the proposed operation remains forbidden.

### Security decision principle

**Authorization must be evaluated at the point where a protected operation is requested, not inferred solely from the original prompt decision.**

---

## 7. Intent Analysis and Security Orchestration

The intent-analysis stage connects the initial prompt pipeline to the resource-specific guards.

Its responsibility is to determine which capabilities the agent proposes to use.

For example:

```text
Task:
Generate a report using stored customer data
and submit the report through an external service.
```

The analysis may identify:

```text
1. Read persistent memory.
2. Process the retrieved data.
3. Invoke an external tool.
4. Potentially access an authentication secret.
```

These identified actions are then evaluated by their respective guards.

```text
                    Intent Analysis
                           |
              +------------+------------+
              |            |            |
              v            v            v
         MemoryGuard    ToolGuard    SecretGuard
              |            |            |
              v            v            v
          Read policy   Tool policy   Secret policy
              |            |            |
              +------------+------------+
                           |
                           v
                  Orchestration Layer
                           |
                           v
                   Execution Control
```

The intent-analysis model is not a replacement for authorization.

Its output is a proposed action plan, not proof that the requested operations are safe.

### Handling inconsistent results

Different guards may return different decisions for a multi-step task.

For example:

```text
MemoryGuard: ALLOW
ToolGuard:   ALLOW
SecretGuard: DENY
```

The orchestrator must not interpret two positive decisions as permission to ignore the third.

Instead, it must enforce the policy applicable to each operation and prevent dependent operations from proceeding when a required authorization fails.

The exact aggregation rules should be defined explicitly in the implementation.

---

## 8. Security Model

ASO is designed around several security principles.

### 8.1 Defense in depth

No single detector or security application should be responsible for preventing every possible attack.

Prompt inspection, memory authorization, tool governance, and secret protection address different stages of execution.

### 8.2 Least privilege

Agents and tools should receive only the permissions needed for their intended operations.

A tool's existence does not grant unrestricted authority over every resource it can technically access.

### 8.3 Default-deny authorization

Protected operations should be denied when the system cannot establish the required authorization.

This is especially important for secret access and sensitive memory operations.

### 8.4 Explicit resource authorization

Each sensitive operation should be evaluated against relevant information, including:

- Requesting agent.
- Tool identity.
- Requested operation.
- Intended destination.
- Resource definition.
- Developer policy.
- Global security policy.
- Relevant execution context.

The exact checks depend on the resource type.

### 8.5 Separation of detection and authorization

Detecting a secret is not the same as authorizing its use.

Detecting a suspicious prompt is not the same as determining whether every subsequent operation is forbidden.

Similarly, classifying tool output as suspicious is not the same as deciding whether the tool itself was authorized.

ASO keeps these responsibilities separate so that security decisions can be made at the appropriate layer.

### 8.6 Minimize sensitive-data exposure

Sensitive credentials and protected information should not be copied into the LLM context unnecessarily.

Where possible, operations should be performed by controlled components that return only the information required for the current task.

### 8.7 Fail-closed behavior

If a required security control is unavailable, fails unexpectedly, or cannot establish authorization, the system should prevent the protected operation from proceeding unless an explicitly defined and safe recovery policy applies.

A detector failure must not silently become authorization.

---

## 9. Security Boundaries and Limitations

ASO introduces security controls around agent operations, but its effectiveness depends on how it is integrated.

The framework should not be treated as an unconditional guarantee against all AI-agent attacks.

### Prompt inspection limitations

A prompt detector may fail to identify an attack, particularly when instructions are obfuscated, embedded in indirect content, or expressed in an unfamiliar form.

For this reason, downstream resource controls remain necessary.

### Tool execution limitations

ToolGuard can evaluate requests only when the execution path passes through its enforcement mechanisms.

If an agent or tool has an alternative path to a protected system, the policy can be bypassed.

### Memory isolation limitations

MemoryGuard cannot guarantee that all memory access is controlled if the agent has direct access to database credentials or can establish an independent connection to the underlying backend.

Enforcement should therefore be supported by database permissions, credential isolation, and controlled connectivity.

### Secret protection limitations

Encryption at rest protects stored data under specified threat assumptions, but it does not automatically prevent plaintext exposure while a secret is actively being used.

Application compromise, leaked KMS credentials, malicious tools, and compromised processes may still expose secrets.

### Intent-analysis limitations

An AI model may misunderstand a task or produce an inaccurate description of its intended actions.

Security-critical authorization decisions should therefore rely on enforceable policies and validated operation metadata rather than the model's explanation alone.

### Integration limitations

The framework can enforce only the security properties supported by its actual implementation and integration points.

A security application should not be described as protecting a resource until the relevant access path is connected to that application and tested.

---

## 10. Intended Integration Model

ASO is intended to be integrated into AI-agent applications as a security orchestration layer.

A typical integration should follow this logical sequence:

1. Receive a user prompt.
2. Submit the prompt to PromptGuard.
3. Evaluate the prompt result through the Decision Engine.
4. Stop or quarantine the request when required.
5. Run intent analysis for accepted requests.
6. Identify proposed memory, tool, and secret operations.
7. Send each protected operation through the relevant guard.
8. Enforce the resulting authorization decision.
9. Inspect relevant tool outputs and memory results.
10. Return only permitted results to the agent.
11. Record security-relevant events without exposing sensitive values.

### Integration requirement

**The framework must mediate the actual resource operation, not merely inspect a description of the operation.**

For example, checking a proposed database read is insufficient if the agent can execute the same read through a separate, unmonitored database connection.

The same principle applies to tools and secrets.

---

## 11. Project Structure

The repository currently contains the implementation packages, a `src/aso` public API, examples, and release documentation.

```text
AgentSecurityOrchestrator/
│
├── src/aso/
│   ├── __init__.py
│   └── public service wrappers
│
├── docs/
│   ├── aso_tutorial.md
│   └── publishing.md
│
├── examples/
│   └── secure_tool.py
│
├── .github/workflows/
│   ├── ci.yml
│   └── publish.yml
│
├── PromptGuard/
│   ├── analyser/
│   └── prompt_inspection/
│
├── DecisionEngine/
│   ├── aso_core.py
│   ├── config.py
│   └── db.py
│
│
├── memoryGuard/
│   ├── memory_guard.py
│   ├── memory_access_layer.py
|   ├── memory_gateway.py
│   ├── config.py
│   └── db.py
│
├── SecretGuard/
│   ├── tool_secret_guard.py
│   ├── secret_guard.py
|   ├── secret_gateway.py
│   ├── db.py
│   └── config.py
│
│
├── ToolGuard/
│   ├── config.py
│   ├── db.py
│   └── tool_guard.py
│
├── pyproject.toml
└── README.md
```

`Quick_start.md` points to the complete tutorial for compatibility with existing links.

---

## 12. Testing Strategy

A security framework requires more than ordinary unit tests.

Testing should validate both the behavior of individual components and the enforcement of security boundaries.

### PromptGuard tests

Test cases should include:

- Benign prompts.
- Explicitly suspicious prompts.
- Instructions attempting to override security controls.
- Prompts containing sensitive information.
- Borderline cases.
- Unexpected detector failures.

Verify that the Decision Engine handles each outcome according to policy.

### Decision Engine tests

Verify that:

- `DENY` prevents normal downstream execution.
- `QUARANTINE` prevents automatic continuation.
- `ACCEPT` enables the next stage without granting unrestricted resource access.
- Failures in required security controls do not silently grant permission.
- Conflicting guard decisions are handled according to the defined policy.

### MemoryGuard tests

Verify that:

- Authorized reads and writes can proceed.
- Unauthorized operations are denied.
- Untrusted content is handled according to policy.
- Database access cannot bypass the controlled access layer.
- Adapter errors do not silently bypass authorization.

### ToolGuard tests

Verify that:

- Undefined tools cannot be invoked through the controlled path.
- Unauthorized operations are rejected.
- Destination restrictions are enforced.
- Tool outputs are inspected.
- Sensitive output is not passed to the LLM without the required checks.
- Tool execution errors cannot bypass security controls.

### SecretGuard tests

Verify that:

- Unregistered secrets are not automatically trusted.
- Unauthorized secret access is rejected.
- Secret values do not appear in logs or audit records.
- Encrypted data can be decrypted only through the authorized key-management path.
- Secret rotation and revocation behave as specified.
- Secret values are not unnecessarily exposed to the LLM.

### Integration tests

Integration tests should simulate complete agent workflows involving multiple guards.

For example:

```text
Accepted prompt
      |
      v
Intent analysis
      |
      v
MemoryGuard: ALLOW
      |
      v
ToolGuard: ALLOW
      |
      v
SecretGuard: DENY
      |
      v
Protected operation does not proceed
```

These tests are particularly important because a system can pass individual unit tests while still allowing unauthorized actions through incorrect orchestration.

---

## 13. Development Roadmap

The following roadmap describes possible development priorities. It does not imply that unfinished work is already implemented.

### Phase 1: Core orchestration

- Define shared decision and security-context models.
- Finalize the Decision Engine interface.
- Define the contract between prompt inspection and intent analysis.
- Establish error-handling and fail-closed behavior.

### Phase 2: PromptGuard

- Complete the inspection pipeline.
- Establish detector interfaces.
- Build benign, suspicious, and borderline test datasets.
- Validate Decision Engine integration.

### Phase 3: MemoryGuard

- Finalize read and write authorization.
- Implement the memory access layer.
- Add supported database adapters.
- Enforce controlled access to the underlying storage.
- Add operation auditing and integration tests.

### Phase 4: ToolGuard

- Finalize tool definitions and policies.
- Enforce pre-execution authorization.
- Implement post-execution output inspection.
- Validate destination and operation restrictions.
- Test failure and bypass scenarios.

### Phase 5: SecretGuard

- Finalize secret registration and permission models.
- Implement SecretBroker.
- Implement encrypted secret storage.
- Integrate key management.
- Prevent unnecessary plaintext exposure.
- Implement rotation, revocation, and auditing.
- Test secret-leakage scenarios.

### Phase 6: Cross-component orchestration

- Connect all guards to the shared execution workflow.
- Define the behavior for conflicting decisions.
- Test multi-step tasks involving multiple resources.
- Validate that protected operations cannot bypass the relevant guards.

### Phase 7: Hardening and release preparation

- Add adversarial integration tests.
- Review dependency security.
- Test configuration failures.
- Document supported environments and limitations.
- Define a stable public API.
- Establish versioning and release procedures.

---

## 14. Design Principles

ASO follows these architectural principles:

**Modularity**  
Each security application addresses a distinct part of the agent attack surface.

**Explicit decisions**  
Security outcomes should be represented explicitly rather than hidden inside agent reasoning.

**Policy-driven authorization**  
Sensitive operations must be checked against defined security policies.

**Least privilege**  
Resources should be available only to authorized requesters and operations.

**Controlled execution**  
Security checks must be enforced at the actual resource boundary.

**Sensitive-data minimization**  
Credentials and confidential information should be exposed only when necessary.

**Defense in depth**  
A successful initial prompt inspection does not eliminate the need for downstream controls.

**Testability**  
Security behavior should be verifiable through unit, integration, and adversarial tests.

**Extensibility**  
New detectors, database adapters, tools, and secret types should be added without unnecessarily rewriting the central orchestration layer.

---

## 15. Project Status

ASO is being developed as a modular AI-agent security framework.

The current development work described for the project includes:

- Engineering design for PromptGuard.
- Engineering design for MemoryGuard.
- Engineering design for ToolGuard.
- Engineering design for SecretGuard.
- A Decision Engine that processes prompt-inspection outcomes.
- An intent-analysis stage that identifies proposed agent actions and routes them to relevant security applications.

The distinction between architectural design, implemented functionality, and independently validated security guarantees is important.

Specific capabilities should be considered implemented only when the corresponding code and tests are available.

Before describing ASO as production-ready, the project should validate the enforcement boundaries, error-handling behavior, secret-handling guarantees, and integration paths of each component.

---

## 16. Security Disclaimer

ASO is a security engineering project intended to help developers introduce additional security controls into AI-agent applications.

It should not be considered a substitute for:

- Secure application architecture.
- Correct identity and access management.
- Database-level authorization.
- Secure credential management.
- Network security.
- Sandboxing and process isolation.
- Security testing and independent review.

No single prompt detector, AI classifier, or orchestration framework can guarantee complete protection against every AI-agent attack.

Security guarantees depend on the implementation, deployment environment, configuration, and enforcement of the relevant controls.

Do not use the framework to protect production secrets or sensitive systems until the relevant security controls have been implemented, tested, and reviewed.

---

## 17. Contributing

Contributions should preserve the modular architecture and the separation between detection, authorization, orchestration, and resource execution.

Useful contributions include:

- New prompt-inspection techniques.
- Additional memory database adapters.
- Tool authorization and output-inspection improvements.
- Secret detection and storage improvements.
- Policy-engine improvements.
- Adversarial test cases.
- Documentation and integration examples.

Contributors should include tests for security-sensitive changes.

---

## 18. Vision

The long-term goal of AgentSecurityOrchestrator is to provide a reusable security layer that developers can integrate into AI-agent applications without having to implement every security control independently.

ASO approaches agent security as a coordinated system:

```text
Prompt Inspection
        |
        v
Decision Orchestration
        |
        v
Intent and Task Analysis
        |
        v
Resource-Specific Authorization
        |
        v
Controlled Execution
        |
        v
Output Inspection
        |
        v
Protected Agent Workflow
```

By separating initial prompt inspection from resource-level authorization, ASO aims to make security controls more modular, auditable, and enforceable throughout the AI-agent lifecycle.

**The objective is not merely to detect malicious prompts. It is to control what an AI agent is permitted to do after receiving them.**