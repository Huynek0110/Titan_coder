# Tool catalog

The UI exposes the catalog count, but Qwen receives only a focused subset selected from the current intent and mode.

## Conversation and project context

- `ask_user` — pause for missing information or a real product decision.
- `update_plan` — publish a short, checkable plan.
- `spawn_subagents` — run up to three read-only explorer/reviewer/researcher/tester tasks at depth 1.
- `system_info` — non-secret OS/runtime facts.
- `current_time` — local and UTC time.
- `project_memory` — small project-scoped preferences and facts.

## Files and project analysis

- `list_directory`
- `find_files`
- `read_file`
- `read_many_files`
- `search_text`
- `get_file_info`
- `write_file`
- `edit_file`
- `apply_patch`
- `create_directory`
- `move_file`
- `delete_path` — uses the Windows Recycle Bin when Electron provides it.
- `project_overview`
- `project_map`
- `find_symbols`

File paths are canonicalized and contained inside the selected workspace. Common build/dependency folders are omitted from broad scans.

## Terminal, Git and verification

- `run_command`
- `start_process`, `read_process`, `list_processes`, `stop_process`
- `git_status`, `git_diff`, `git_log`, `git_blame`
- `list_project_tasks`
- `run_test`, `run_lint`, `run_format`
- `open_path`

Generic terminal commands are intentionally powerful. They are code execution, not a security sandbox.

## Web

- `web_search` — Brave Search with a key or DuckDuckGo fallback.
- `web_fetch` — bounded, readable extraction of an HTTP(S) page.
- `http_request` — bounded GET/POST/PUT/PATCH/DELETE/HEAD request.

Local, private, link-local, metadata, credential-bearing, and private-redirect targets are blocked. Returned web content is marked untrusted in the model prompt.

## MCP

Configured tools appear as `mcp__server__tool`. They support stdio and Streamable HTTP transports. Tool names, descriptions, schemas, calls, and results are bounded; every external server is treated as untrusted.
