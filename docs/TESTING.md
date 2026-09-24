# Testing

All automated checks are finite and do not call the language model.

```powershell
npm.cmd run check
npm.cmd test
npm.cmd run smoke
```

`npm.cmd run smoke` launches Electron with an isolated user-data directory and a hard 20-second startup budget, captures a screenshot to `artifacts/`, and always kills its process tree in `finally`.

## Manual LM Studio acceptance

Use a loaded Qwen model in a temporary test workspace.

1. Ask `Bây giờ là mấy giờ?` — activity should show a time tool and a natural answer, never raw `<call>` or tool JSON.
2. Create a disposable `hello.js`, ask for a bug fix, inspect the edit, then run its test — tool cards should remain separate from the final answer.
3. Request a broad architecture review — activity should show subagent cards and one parent summary.
4. Leave a required parameter unknown — an ask-user dialog should appear before any mutating tool.
5. Start a long command and press Stop — the run should become cancelled and the process should be stopped.
6. Configure a known stdio MCP server — it should appear as `mcp__server__tool` and reload without exposing its token.

Live model checks are intentionally not part of `npm test`, because a loaded local model can take several minutes on CPU and make CI appear hung.
