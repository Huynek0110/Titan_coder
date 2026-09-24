# Architecture

## Trust boundary

Qwen is treated as an unreliable planner. It can request a tool, but it cannot execute code, read a secret, choose a workspace boundary, or mark its own work complete. The Electron main process owns those decisions.

```text
Renderer (sandboxed)
  │ typed IPC / user events
  ▼
AgentRunner
  ├─ focused tool catalog (a small relevant subset)
  ├─ LM Studio streaming adapter
  ├─ one-tool-per-turn policy
  ├─ schema validation + conservative Qwen fallback parser
  ├─ clarification / approval interactions
  └─ bounded recursive subagents
          │
          ▼
ToolBroker
  ├─ WorkspaceTools (canonical path containment)
  ├─ SystemTools (shell, Git, processes, tests)
  ├─ WebTools (redirect + SSRF checks)
  └─ McpManager (stdio / Streamable HTTP)
```

## Run loop

1. Persist the user message and create an `AbortController`.
2. Build a bounded context from recent user/assistant messages.
3. Select a focused tool subset from the full catalog.
4. Stream one model response.
5. If LM Studio returns `tool_calls`, validate the name and JSON arguments with Ajv.
6. For Qwen releases that emit `<call>` but fail adapter parsing, accept only one exact wrapper whose tool name is in the current turn's catalog. Ambiguous calls are never executed.
7. Execute at most the first requested tool. Extra calls receive a policy error.
8. Feed a compact `ok/error` observation back to the model.
9. End on natural text, cancellation, interaction timeout, or budget exhaustion.

## Why not expose every tool every turn?

The catalog contains many capabilities, but Qwen2.5-Coder 14B Q3 performs worse when it must choose among many schemas. Tool definitions are routed by intent and mode. Plan mode has no mutating tools; chat mode has a small web/system set; coding mode receives discovery plus the appropriate edit/test tools.

## Subagents

The parent may call `spawn_subagents` once. Subagents are read-only, cannot ask the renderer directly, cannot spawn more agents, and have independent step limits. They can use workspace discovery, Git, tests, and web research. The parent receives summaries, not a new authority token.

Default limits:

- parent: 12 model/tool steps;
- total subagents: 3;
- concurrent subagents: 2;
- each subagent: 8 steps;
- recursion depth: 1.

## Files and commands

File tools resolve a canonical path immediately before every operation and reject traversal, outside-root absolute paths, and symlink/junction escapes. The workspace root itself cannot be deleted.

`run_command` is not a sandbox. Its working directory is the workspace, but arbitrary shell code can access the rest of the machine. Automatic mode is therefore an explicit trust decision. “Ask first” mode is available for safer use.

## Untrusted external data

Web pages and MCP results are observations, not instructions. Web fetching blocks credentials, non-HTTP schemes, private/local IP ranges, metadata addresses, and private redirects. MCP schemas/results and remote content are size-limited. A final answer never exposes the internal tool envelope.

## Crash and cancellation

Cancellation uses a shared `AbortSignal` from renderer to LM Studio, tool calls, subagents, and child processes. Mutating tools record completion before the model is told they succeeded. A cancelled or interrupted write is never described as rolled back unless the tool proved it.
