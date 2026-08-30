# MCP: asking the estate questions

`patchwright serve` also speaks the [Model Context Protocol](https://modelcontextprotocol.io)
at `/mcp`, so an LLM client can ask the questions people already ask - *what does the
payments team need to fix?*, *what would rebuilding topnotch's base actually clear?* -
and get them answered from the assessment rather than from a screenshot somebody
pasted.

It is the same process, the same cached assessment and the same authentication as the
API. There is no second deployment, no second copy of the config, and a tool answer is
exactly as fresh as the page is, because it is the same object.

## Tools

All read-only. Each is one question somebody actually asks, answered completely,
rather than a wrapper around an endpoint - a model given a REST client asks three
calls and a join to learn what a page shows at a glance, and gets the join wrong often
enough to matter.

| Tool | Answers |
|---|---|
| `estate_summary` | The headline: size of the problem, how much of it rebuilds would clear, the biggest wins, and what nobody is acting on |
| `service_report` | Everything about one service: deployments, image age, the upgrade it needs, and exactly what that upgrade clears, leaves and introduces |
| `worst_first` | The work queue, worst first, filterable by team, priority and exposure |
| `team_report` | One team's whole position, including what is already in flight and what is merely open and stale |
| `explain_cve` | One CVE across the estate: who carries it, whether any of them is exposed, and where a rebuild removes it |

`service_report` is the deep one. Asked about a service it returns the split that
turns a number into a conversation:

```
apps/topnotch - payments - urgent in prod, internet-facing
  3 deployments, newest image built 187 days ago
  10 CVEs, 1 known-exploited

  Upgrade: mcr/dotnet/aspnet 9.0 -> 10.0 (version change, not a rebuild)
    clears 6, leaves 2, introduces 1

  What survives:
    2 still in the new base   - upstream's, no action available here
    2 from the application    - installed by the build, the team's
    remainder concentrated in: zlib (2)
```

Two rules hold across every tool, and both exist because prose loses what a table
keeps.

**Every answer carries its freshness** - when the assessment ran, how old the scan
provider's own data is, and which build answered. "Nothing is exploitable in
production" means something different against data from an hour ago and from a
fortnight ago, and a model asked to summarise will drop that unless it is in the
payload.

**Absence never renders as zero.** An unassessed image is not a clean image. Every
answer states its coverage, and each carries a `caveats` list saying what it cannot
support - because nobody re-reads a sentence a chatbot produced.

## Connecting

The endpoint is Streamable HTTP at `/mcp`.

```sh
patchwright serve -i export.csv -c config/ --addr :8080
```

Then point a client at `http://localhost:8080/mcp`. In Claude Code:

```sh
claude mcp add --transport http patchwright http://localhost:8080/mcp
```

With a token configured, pass it as a header:

```sh
claude mcp add --transport http patchwright http://localhost:8080/mcp \
  --header "Authorization: Bearer $PATCHWRIGHT_API_TOKEN"
```

## Authentication

Nothing new. `/mcp` is a normal route, so it inherits the middleware that wraps
everything else: the shared token is required where one is configured, and the
endpoint is open where nothing is. Mounting it as an exempt path would have put an
unauthenticated read of the whole estate on the same port as a page that is behind
sign-in, and network policy selects on port rather than path.

One interaction worth stating, because a client cannot report it usefully.
Interactive sign-in and the shared token are alternatives in the same middleware, and
an MCP client is not a browser: with sign-in configured and no token set, a headless
caller has no way to authenticate. It fails clearly - a non-HTML request gets a 401
telling it to present a token rather than a redirect into a login page - but the
answer is to set the token alongside sign-in wherever machine callers are expected.

Authorisation is unchanged and all-or-nothing: whatever reaches the endpoint sees the
whole estate, because the underlying views have no per-team scoping to offer.

## What is deliberately absent

**No `refresh` tool.** It is the one expensive operation - on a real estate around
twenty-five minutes and several GB - and a scheduled assessment already keeps the
cache current. Leaving it out removes the rate-limiting question entirely: reads are
map lookups, so a client calling in a loop costs nothing worth defending against.

**No write tools.** The ticket plan is already exposed read-only with an explicit
apply, and moving that behind a conversational interface deserves its own decision
rather than arriving as a side effect of this one.

**No stdio transport.** It would mean one process per client, each holding its own
credentials and running its own twenty-five-minute assessment before it could answer
anything. Fine for a tool that reads local files; not for this.
