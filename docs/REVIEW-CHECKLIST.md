# Review checklist

Use independent reviewers; do not let the first reviewer mark its own findings resolved.

## Security

- Renderer has no Node integration, no arbitrary navigation, strict CSP, and a narrow preload API.
- No AbortSignal, token, authorization header, or internal object is sent over IPC.
- Workspace containment handles traversal, absolute paths, case, ADS/device/UNC, symlink and junction escapes.
- SSRF checks cover DNS, IPv4/IPv6 private ranges, every redirect, credentials, ports, and metadata endpoints.
- MCP stdio/HTTP cannot corrupt the protocol stream, leak stderr secrets, or exceed timeout/result limits.
- Invalid tool schemas fail closed; unknown fields and mutating operations cannot bypass approval mode.
- Logs and public settings redact secrets.

## Agent correctness

- At most one tool executes per model turn.
- Tool arguments are parsed, bounded, and schema-validated.
- Qwen fallback parsing accepts only exact, unambiguous, allow-listed single calls.
- Malformed/raw tool JSON is never displayed or executed ambiguously.
- `ask_user` is reachable and blocks further work until answered.
- Plan mode and subagents cannot mutate files, run arbitrary commands, spawn agents, or directly control UI.
- Cancellation propagates through fetch, model generation, tools, subagents, and child processes.
- Recursive, concurrent, step, output, and context budgets are enforced.
- Tool results stay compact and compatible with Qwen's Jinja tool template.

## UI/UX

- First-run LM Studio setup is understandable for a novice.
- Server/model/workspace states are accurate and actionable.
- Tool and subagent activity is readable without showing protocol JSON.
- Streaming never flashes malformed Markdown/HTML or duplicates assistant text.
- Keyboard, focus, dialogs, light/dark themes, narrow windows, and long paths are usable.
- Stop/cancel and interaction states cannot deadlock the UI.

## Performance and resilience

- No overlapping status polls or leaked Electron/Node process trees.
- Rebuilding tool sources does not orphan background processes.
- MCP startup failure does not block the app.
- Session writes are serialized/atomic and corruption recovers safely.
- Tool scans and command output have hard limits.
- Large repositories avoid unbounded recursion and synchronous event-loop blocking.
- Packaged app includes all runtime assets and starts without dev dependencies.

## Verification

- Unit tests are finite and use fakes/temp directories.
- Electron smoke test always kills its process tree.
- No routine automated test calls a live local model.
- Manual LM checks cover raw `<call>`, fenced tool JSON, clarification, cancellation, tests, and subagents.
