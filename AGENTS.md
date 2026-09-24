# Agent handoff rules

- Workspace: `D:\Coder_locally`.
- Node/Electron commands must have a hard timeout and must kill their process tree; never leave a background `node`, `electron`, `npm start`, or live-model probe running.
- Do not edit files assigned to another active agent. Read-only review is preferred until ownership is explicit.
- Main-process code is CommonJS and runs with `contextIsolation: true`, `nodeIntegration: false`, and sandboxed renderer.
- Model output is untrusted. Never expose raw tool protocol, JSON envelopes, tokens, or internal objects to the renderer.
- File tools are workspace-contained. Terminal and Web/MCP are high-risk capabilities and require policy checks at execution time, not only in the prompt.
- After integration: run `npm.cmd run check`, `npm.cmd test`, and finite `npm.cmd run smoke`; then make a local Git backup commit before starting the next review cycle.
- Review findings are prioritized as P0 security/correctness, P1 reliability, P2 performance/UX. A reviewer must not mark its own changes resolved without a second pass.
