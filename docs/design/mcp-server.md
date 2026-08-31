# Design: MCP server for patchwright

Status: **shipped**, read-only. Seven tools at `/mcp` in the `serve` process, behind
the same authentication as everything else. See [docs/mcp.md](../mcp.md) for what
they answer; this note records why the shape is what it is.

The tool list below is what was PROPOSED, kept for the record. What shipped is
deeper: the questions people ask are about a SERVICE or a TEAM, not about a finding,
so `service_report` and `team_report` absorbed `explain_finding`, `list_findings`,
`biggest_wins` and `not_addressed` rather than each being its own thin wrapper. Open
question 2 was the reason - the original list was inferred from what the page shows
rather than from anybody's questions.

Two arrived later, from using it. `fix_plan` because a report and an instruction are
not the same artefact: somebody holding a ticket wants the change to make and what
NOT to do, not a dataset to interpret. `list_facets` because a filter guessed wrong
returns an empty result, and an empty result reads as an empty queue - so the
vocabulary had to be askable. See [docs/mcp.md](../mcp.md) for what shipped.

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

## Tools, as proposed

Superseded - see [docs/mcp.md](../mcp.md) for the seven that shipped. Read-only, and
deliberately a thin mapping onto views that already exist, so there is no second
definition of what a finding is.

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

## Authentication: whatever the API already uses

Nothing new. The MCP endpoint registers in the same route table as everything else
and inherits the middleware that wraps it, which already has exactly the behaviour
wanted:

- a shared token is configured, and the endpoint requires it
- nothing is configured, and the endpoint is open, like the rest of the service

That is the whole design. Mounting it as a normal route rather than an exempt one
also removes the failure worth avoiding: an exempt path would put an
unauthenticated read of the estate on the same port and hostname as a page that is
behind sign-in, and network policy cannot separate them because it selects on port
rather than path. Inheriting the middleware means the endpoint can never be the
weakest door into the same room.

Where something in front already authenticates callers, run without a token and let
it. Re-checking a credential behind a component that has already decided who the
caller is buys nothing and adds a secret to manage. That is a deployment decision
rather than a code one, which is the point: the service does not need to know.

One interaction to state, because it will otherwise be discovered by a client that
cannot report it usefully. Interactive sign-in and the shared token are alternatives
in the same middleware, and an MCP client is not a browser: with sign-in configured
and no token set, a headless caller has no way to authenticate. It does at least
fail clearly - a non-HTML request gets a 401 saying to present a token, rather than
a redirect into a login page - but the answer is to set the token alongside sign-in
wherever machine callers are expected.

Authorisation is unchanged and all-or-nothing: whatever reaches the endpoint sees
the whole estate, because the underlying views have no per-team scoping to offer. If
something in front enforces narrower access, that narrowing cannot be enforced here.

## Cost

A Go MCP SDK is a new dependency in a tool that ships a deliberately small one. It
is worth weighing rather than assuming: the alternative is implementing the protocol
directly, which is a JSON-RPC framing over HTTP and is not large, but is also not
free to maintain against a moving spec. Prefer the official SDK if it is stable
enough by the time this is built.

## Phasing

1. Tool implementations over the existing cached assessment, wired to the CLI's
   stdio transport. No server change, no network question, testable.
2. Streamable HTTP at `/mcp` on the existing server, behind whatever authentication
   the API already has.

## Open questions

1. **Does the freshness qualification survive summarisation?** It can be in every
   payload and still be dropped by the model. Worth testing with real questions
   before trusting it, because a confidently stale answer is worse than the page.
2. **Which questions do people actually ask?** The tool list above is inferred from
   what the page shows rather than from anybody's questions, and the two are not the
   same thing.
3. **Does this want rate limiting?** A conversational client can call a tool in a
   loop. Reads are cheap, but `refresh` is not, and the API has no limiting today.
   Whether that belongs here or in front of it is worth settling before a client
   discovers it.
4. ~~**Is `refresh` a tool at all?**~~ **Settled: no.** Leaving it out removed the
   rate-limiting question in 3 with it - every remaining tool is a map lookup over
   the cached assessment, so a client calling in a loop costs nothing worth
   defending against.
