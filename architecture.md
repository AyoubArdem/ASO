# ASO Architecture

## Overview

ASO is a fail-closed security orchestration framework for AI agents. It introduces a dedicated enforcement boundary between an agent and the resources it may access.

The core idea is simple: a model may propose actions, but it must not gain access to memory, tools, or secrets unless each resource path has passed explicit policy checks.

## Security layers

1. PromptGuard
   - inspects the user prompt and embedded instructions
   - identifies unsafe, malicious, or policy-bypassing requests
   - produces a security decision before the agent continues

2. DecisionEngine
   - central coordinator
   - interprets prompt and guard decisions
   - routes requests to the correct guarded layer
   - prevents unauthorized execution paths

3. MemoryGuard
   - validates memory reads and writes
   - checks identity, store ownership, and allowed operations
   - stops untrusted or dangerous memory access

4. ToolGuard
   - authorizes tool invocation
   - validates tool purpose and destination
   - inspects tool results before returning them to the agent

5. SecretGuard
   - protects API keys and secret material
   - enforces policy-based access and brokered retrieval
   - prevents secret leakage into agent context or logs

## Execution flow

```text
User input
    |
    v
PromptGuard
    |
    v
DecisionEngine
    |
    +--> DENY / QUARANTINE / ACCEPT
                  |
                  v
        Intent and task analysis
                  |
                  v
      +-----------+-----------+
      |                       |
      v                       v
MemoryGuard              ToolGuard
      |                       |
      v                       v
   SecretGuard (if needed)
      |
      v
Authorization result
      |
      v
Controlled execution
```

## Design principles

### Defense in depth
No single layer should be the only protection boundary.

### Least privilege
Agents only receive the permissions needed for the current task.

### Default deny
If trust cannot be established, the request is denied.

### Fail closed
Security failures stop the operation instead of silently continuing.

### Separation of concerns
Prompt inspection, request routing, and resource authorization are distinct responsibilities.

## Public library API

The public package exposes these high-level services:

- `AgentSecurityOrchestrator.process`
- `PromptAnalyser`
- `MemoryGuard`
- `ToolGuard`
- `SecretGuard`

These are intended to be used by application developers as security boundaries for AI agents.

## Production expectations

For production use, ASO should be integrated with:

- a trusted authentication context
- explicit, policy-driven access lists
- secure key management for secrets
- versioned auditing and event logging
- model/provider pluggability for prompt and memory analysis

## Summary

ASO is built to protect AI agents from prompt injection, unsafe tool calls, memory abuse, and secret exposure. The architecture is intentionally layered so that each protected resource is governed independently and all decisions remain explicit and auditable.
