# Design: MCP server for patchwright

Status: **proposed** (planned for later — agreed)

## Why

The CLI is great for platform/security engineers, but less-technical
stakeholders (engineering leads, risk, product) want answers, not flags:
*"what critical vulnerabilities does the payments team need to fix?"*,
*"is anything actionable in production right now?"*.

An [MCP](https://modelcontextprotocol.io) server exposes patchwright's
assessment as structured tools an LLM client (Claude Desktop, IDEs, chat) can
call, so anyone can ask in natural language and get grounded, owner-attributed
answers — no CLI, no CEL.

## Shape

A `patchwright mcp` subcommand serving MCP over stdio, built on the **same
pipeline library** the CLI uses (no logic duplicated). It reads the same
provider + config configuration.

```
patchwright mcp --provider rapid7 --input <...> --config <...> [--live-source kube ...]
```

### Tools (read-only first)

| Tool | Purpose |
|---|---|
| `profile` | Volume + dedupe headroom + breakdowns — the noise overview. |
| `list_findings` | Actionable findings, filterable by `owner`, `team`, `priority`, `actionable_only`, `live_only`. |
| `explain_finding` | For one image: owner, verdict, the rules that matched, affected workloads/accounts, and (with Trivy) the fixable CVEs. |
| `owners_summary` | Counts of actionable findings per owner class / team — a leaderboard for triage. |

All return **structured JSON** (the existing finding view), so the client can
render tables or prose. Read-only to start; later, guarded write tools
(`create_jira_ticket`, `open_fix_pr`) once those sinks exist.

### Implementation notes

- Use a Go MCP SDK (e.g. the official `modelcontextprotocol/go-sdk` or
  `mark3labs/mcp-go`); wrap `pipeline.Run` + the sink views.
- Cache the last assessment; expose a `refresh` tool rather than re-running on
  every call.
- Ship it in the same binary/image; a Helm value toggles a long-running MCP
  Deployment vs the assessment CronJob.

## Dependencies / phasing

- Best **after Trivy** (so `explain_finding` can talk about *fixable* CVEs).
- Phase 1: read-only tools (`profile`, `list_findings`, `explain_finding`,
  `owners_summary`) over stdio.
- Phase 2: write tools gated behind the Jira / GitOps sinks.

## Open questions

- **Auth/scoping** for multi-user access if hosted centrally (vs each user
  running it locally against read-only creds).
- **Freshness** — surface the export/scan timestamp so answers state how current
  they are.
