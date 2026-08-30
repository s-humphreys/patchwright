# Design: onboarding a team onto automated updates, slowly

Status: **proposed, not built.** This is a plan to walk through, not a description of
something that exists.

## The problem

The queue can already say which service is worst, why, and what would fix it. What it
cannot do is get anybody to act, and the honest reading of the estate is that most of
the queue is not neglect: an image drifts because nothing ever opens the pull request
that would move it, and nobody has time to open several hundred by hand.

An update bot solves exactly that, and one is already running. So the question is not
"should we automate updates" but "why is a service that obviously needs it not on it,
and what is the smallest step that gets it there".

The smallest step matters more than it sounds. A team's first experience of this
decides whether they engage with the queue at all, and the failure mode is not
resistance - it is forty pull requests on a Monday morning, which teaches everyone
that security automation is something to mute.

## How the bot actually gets enabled today

Worth stating plainly, because the design turns on it.

The bot discovers repositories across several projects and applies one shared
configuration. It does **not** raise onboarding pull requests. With that combination
its default is to skip any repository that does not already contain a configuration
file of its own.

So a repository is opted in by a file existing in it, and opted out by that file being
absent. That is already the per-repository switch this design needs, which means the
work is not building an opt-in mechanism - it is deciding **which** repositories to
flip, producing the change, and keeping the first week quiet enough that anybody wants
a second one.

## Shape

Three pieces, and the split is deliberate.

**1. A shared preset, centrally owned.** One file in the platform repository holding
the pilot configuration: what gets updated, how often, how many pull requests at once.
A repository opts in with a config that extends it and says nothing else:

```json
{ "extends": ["local>platform/infra:renovate/pilot"] }
```

The whole point is that the one-line file is the ONLY thing in the service repository.
Every noise decision stays central, so when the first pilot proves too chatty it is
tuned in one place rather than in nine repositories that have already drifted apart.

**2. Patchwright chooses the candidates and drafts the change.** It already knows which
services carry known-exploited CVEs, which sit above the exploitation-probability
threshold, and which have had a fix available for a month with nothing started. That
is the ranking a pilot should follow, and it is the argument to the team: not "you are
behind" but "these three of your repositories account for most of it, and here is the
change that keeps them current".

**3. Ticket routing stays as it is.** Routes already carry a CEL expression over the
owner and override the board, issue type and labels per team, which is what "every
team has a different board and template" needs. Nothing new is required, and the
onboarding proposal should reuse the route that already exists for that team rather
than inventing a second way to describe the same thing.

## Keeping the first week quiet

This is the part that decides whether the pilot survives, and the current central
configuration is tuned for a mature repository rather than a nervous one. Concretely,
concurrent and hourly pull request limits are both unlimited today. On a service that
has not been deployed in a year, that is the forty-pull-request Monday.

The pilot preset should differ from the default in four ways:

- **A cap on open pull requests.** Two at a time. A team clears them and gets two more,
  which reads as a trickle rather than a dump.
- **A schedule.** Weekly, early on a working day. Nobody wants to discover this on a
  Saturday.
- **Grouped by what it is.** One pull request for the base image, one for everything
  else. A base image bump is the one that closes most of the queue, and it should not
  arrive buried among lock-file churn.
- **A dashboard issue rather than pull requests for the long tail.** Everything the bot
  COULD do stays visible and only the things worth doing become pull requests.

None of that is novel; it is the difference between the bot's defaults and what a first
week should look like.

## What patchwright would add

Deliberately small, and none of it replaces what the bot does.

- **An onboarding candidate list**, per service and per team, ranked by the policy that
  already exists: known-exploited first, then above the exploitation threshold, then
  fixes available and untouched. Available on the analytics page and over the API.
- **Adoption as a measured fact.** Whether a repository carries the opt-in file, read
  the same way build repositories are already read. Today "is this team on the bot"
  is answered by asking somebody, and it was asked directly in the review that
  prompted this.
- **The proposal itself**: the one-line file, the branch, the pull request body saying
  which findings it addresses and what it will do in the first week. Drafted, never
  applied - the same read-only posture the ticket plan has, for the same reason.

## What this must NOT become

- **Not a replacement for the bot's own logic.** It decides what to update and when;
  this decides which repositories it is pointed at. The moment patchwright starts
  computing versions there are two answers to the same question.
- **Not automatic opt-in.** A repository being bad is not consent. The proposal is
  drafted and a person sends it, because the first pull request into somebody's
  repository is a conversation.
- **Not a second suppression system.** A team that says "not yet" is recorded where
  policy already records such things, with an expiry, not in a new list.

## Where an agent would help, and where it would be a liability

Worth settling now, because "put an agent on it" is easy to say about any of this and
most of it does not want one.

**Nothing in the pipeline above needs a model.** Choosing candidates is a sort over
data the tool already has. The opt-in file is one line of JSON. Reading whether a
repository carries it is an API call. Putting a model anywhere in that chain replaces a
deterministic answer with a probabilistic one, adds a component to deploy, secure and
pay for, and makes the ranking impossible to explain to a team that disputes it - which
is precisely the conversation this exists to have. If a security engineer asks "why is
my service on this list", "it scored highest on the policy you agreed" is an answer and
"the model chose it" is not.

There are three places where the work IS judgement over unstructured text, which is a
different question.

**Is this upgrade going to break me?** The most common objection is not "I disagree" but
"I can't move to that version yet", and it is often right. Deciding it means reading
release notes, migration guides and changelogs - unstructured prose no rule will parse.
A model summarising "what changed between these two versions, and what commonly breaks"
attached to a finding would genuinely save the argument that currently blocks a runtime
upgrade for months. It must be advisory and clearly attributed, never a gate: an
upgrade recommendation is already checkable, and a summary that is confidently wrong
about a breaking change costs more trust than it saves time.

**Turning a finding into words for a specific team.** Low stakes, real value, and a
template gets most of the way there. Worth doing only after the templated version has
been seen to be inadequate, not before.

**Evaluating a team's evidence for why something is not exploitable.** This one is
tempting and should be resisted. The concern already raised is that teams will generate
their justification with a model; having a model assess it produces an exchange where
neither side wrote or read the argument, and no ground truth is ever established. The
answer is an evidence threshold made of verifiable artefacts - a network policy, a
screenshot of a security group, the absence of a route - which is a thing to check
rather than a thing to interpret. Note that the exposure measurement in this tool is
exactly that kind of artefact, and it removes a whole class of the argument by making
the claim checkable.

**A deployable agent that runs the onboarding end to end** is the version to avoid
longest. It would open pull requests into other teams' repositories on its own
judgement, which is the one thing this design says a person should do, and its failure
mode is unattended: a bad batch is discovered by the team receiving it.

## Open questions

1. **Where does the opt-in file land - the service repository or a central list?** The
   file is the bot's own mechanism and needs no permission changes, but it means a pull
   request into a repository the platform team does not own. A central list would keep
   it in one place at the cost of diverging from how the bot expects to be configured.
2. **Adoption needs to be readable.** Reading a file per repository across several
   projects is an API call per repository, which is the same shape as the existing
   build-repository lookup and should reuse whatever that does about rate limits.
3. **What proves it worked?** The honest measure is time from pull request opened to
   merged, per team, and that needs the ticket dates this tool does not yet collect
   (see the note on the analytics page). Without them the pilot can be reported as
   "adopted" but not as "faster", and "faster" is the number that wins the next team.
4. **Does a pilot need its own board?** Routing already supports per-team boards. What
   is unclear is whether a pilot's pull requests should raise tickets at all in week
   one, or whether the pull requests alone are enough and tickets start once the team
   asks for them.
