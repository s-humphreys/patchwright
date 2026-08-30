# Design: MCP server for patchwright

Status: **proposed.** Rewritten after the API server shipped, which changes the
answer to the deployment question this note originally got wrong.

## Why

The CLI and the status page serve people who already know what they are looking at.
The questions that arrive from everyone else are in words: *"what does the payments
team need to fix?"*, *"is anything exploitable in production right now?"*, *"what
would rebuilding that base image actually clear?"*.

Those are answerable from data the tool already has, and the current answer is that
somebody opens the page and reads it out. An MCP server exposes the assessment as
tools an LLM client can call, so the question is asked once and answered from
grounded, owner-attributed data rather than from a screenshot.

## Same deployment, not a separate one

**In the existing `serve` process, mounted on the existing HTTP server.** The
original version of this note proposed stdio and a separate long-running Deployment;
that was written before `patchwright serve` existed and is now the wrong shape.

The reasoning is about where the cost is. Producing an assessment is expensive - on
a real estate around twenty-five minutes, several GB of memory, credentials for ten
clusters, a scan provider and a registry. ANSWERING from one is a map lookup. So:

- **stdio is impractical here.** It means one process per client, each holding its
  own credentials and running its own twenty-five-minute assessment before it can
  answer anything. Fine for a tool that reads local files; not for this.
- **A separate MCP Deployment would either duplicate that cost or proxy the API.**
  If it proxies, it is a translation layer that could equally live in the process it
  is calling, and it doubles the things to deploy, authenticate and keep in step.
- **`serve` already holds exactly what the tools need**: one cached assessment,
  refreshed on a schedule, with the analytics and ticket views computed alongside.

So MCP becomes a transport onto the same cache, over Streamable HTTP at `/mcp`,
registered in the same route table as everything else. `patchwright mcp` over stdio
stays worth having for local use against a local assessment, and is the same tool
implementations behind a different transport.

The practical consequence: no new Deployment, no new Secret, no second copy of the
config, and a tool answer is as fresh as the page is - because it is the same object.

## Tools

Read-only, and deliberately a thin mapping onto views that already exist, so there
is no second definition of what a finding is.

| Tool | Answers |
|---|---|
| `summary` | The estate headline: how much is actionable, coverage gaps, how stale the provider's data is |
| `list_findings` | Findings, filtered by team, priority, signal, exposure, fixability |
| `explain_finding` | One image: the verdict, the rules that produced it, its CVEs, where it runs, and what fixes it |
| `explain_cve` | One CVE across the estate: which images, whose teams, whether a fix exists |
| `biggest_wins` | The base upgrades that clear the most, and the services on each |
| `not_addressed` | The classes of problem nobody is acting on |
| `owner_summary` | Per-team responsiveness |

Every one carries the assessment timestamp and the provider's own data age, because
an answer given in prose loses the qualification a table keeps. "Nothing is
exploitable in production" is a different statement depending on whether the scan
data is an hour or a fortnight old, and a model asked to summarise will drop that
unless it is in the payload.

Absence has to survive the same way. The page is careful that unassessed reads as
"unknown" rather than "clean"; a tool returning zero without saying nothing was
scanned would undo that at the point it matters most, because nobody re-reads a
sentence a chatbot produced.

Write tools - raising a ticket, applying the ticket plan - are deliberately not in
the first phase. The ticket plan is already exposed read-only with an explicit
apply, and moving that behind a conversational interface deserves its own decision.

## The problem worth deciding first: authentication

This is the part that needs an answer before any of the above matters, and it is not
a small one.

The page is protected by OIDC: an interactive browser flow, an identity, and group
membership decided by the provider. That was a security requirement, not a
preference. An MCP client is not a browser and cannot complete that flow the same
way.

Three options, none free:

1. **The existing shared token.** Works today, and throws away the property that was
   asked for: one credential, no identity, no attribution. Acceptable for a
   single-user local client, poor for anything hosted.
2. **MCP's own OAuth flow**, against the same identity provider and app
   registration. Correct, and the most work: authorisation-server metadata,
   dynamic client registration or a pre-registered client, and token validation on
   every call. It reuses the group assignment already in place, so authorisation
   stays where security put it.
3. **Local only.** Each user runs `patchwright mcp` against their own credentials and
   their own assessment, which sidesteps the question and reintroduces the
   twenty-five-minute startup per person.

Option 2 is the right end state. Option 1 is a legitimate first step ONLY if the
endpoint is not reachable beyond the network the token already protects, and the
note should say so plainly rather than letting it become permanent by default.

Authorisation is unchanged either way: whoever gets in sees the whole estate. Every
answer here is derived from a page that has no per-team scoping, so a tool cannot
offer one honestly.

## Cost

A Go MCP SDK is a new dependency in a tool that ships a deliberately small one. It
is worth weighing rather than assuming: the alternative is implementing the protocol
directly, which is a JSON-RPC framing over HTTP and is not large, but is also not
free to maintain against a moving spec. Prefer the official SDK if it is stable
enough by the time this is built.

## Phasing

1. Tool implementations over the existing cached assessment, wired to the CLI's
   stdio transport. No server change, no auth question, testable.
2. Streamable HTTP at `/mcp` on the existing server, behind the shared token, on a
   network where that is already the control.
3. OAuth against the same provider as the page, which is what makes it hostable.

## Open questions

1. **Does the freshness qualification survive summarisation?** It can be in every
   payload and still be dropped by the model. Worth testing with real questions
   before trusting it, because a confidently stale answer is worse than the page.
2. **Which questions do people actually ask?** The tool list above is inferred from
   what the page shows rather than from anybody's questions, and the two are not the
   same thing.
3. **Does this want rate limiting?** A conversational client can call a tool in a
   loop. Reads are cheap, but `refresh` is not, and the API has no limiting today.
