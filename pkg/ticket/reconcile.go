package ticket

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Reconciliation decides what to do about the difference between the tickets that
// exist and the work the assessment says needs doing.
//
// Creating tickets is only the first half. Left alone, a queue rots in three ways,
// all of them observed on a real project within a day:
//
//   - a ticket covering one image of a group suppresses the whole group, leaving
//     the rest with no ticket and nothing saying so,
//   - the version a ticket asks for moves on, so it asks for a stale target,
//   - the work gets done, but the ticket stays open because nothing told it.
//
// Everything here is expressed as an Action so a dry run shows exactly what would
// happen. Notably absent: closing tickets. A finding can vanish because it was
// fixed OR because the provider stopped assessing the image, and those are
// indistinguishable from the queue alone. Closing on the second would quietly
// retire real work, so reconciliation comments and leaves the decision to a human.

// ActionKind is what reconciliation wants done.
type ActionKind string

const (
	// ActionCreate raises a new ticket.
	ActionCreate ActionKind = "create"
	// ActionExtend adds images to an existing ticket that already covers some of
	// the group, so the rest stop being invisible.
	ActionExtend ActionKind = "extend"
	// ActionNoteStale comments that the version the ticket asks for has moved on.
	ActionNoteStale ActionKind = "note-stale"
	// ActionUpdate rewrites a ticket whose target has moved on, rather than
	// commenting, when nobody has picked it up yet. A ticket asking for a version
	// that is no longer the current one wastes the reader's time twice: once
	// working out that the summary is wrong, and again finding the real target in
	// a comment further down.
	ActionUpdate ActionKind = "update"
	// ActionNoteDone comments that the work appears finished, for a human to close.
	ActionNoteDone ActionKind = "note-done"
	// ActionClose closes a ticket whose work is provably done. Only ever emitted
	// on positive evidence — the images are still reported, remediation was
	// checked, and every one is already on the latest available version — never on
	// a finding having disappeared.
	ActionClose ActionKind = "close"
	// ActionHold records a ticket nothing can be said about yet, because the data
	// needed to judge it is missing. Nothing is written: our own blind spot is not
	// news for somebody else's tracker, and a comment about it would be noise on a
	// ticket that is probably fine. Reported so the silence is visible.
	ActionHold ActionKind = "hold"
	// ActionSkip records a ticket that already covers its group correctly.
	ActionSkip ActionKind = "skip"
)

// ActionKinds returns every action kind, in reporting order.
//
// Exists so callers can report on all of them by iteration rather than by hand.
// A hand-listed summary is a silent liar the moment a kind is added: the count is
// computed, the kind is simply missing from the output, and the run looks like it
// did less than it did. That happened — "update" was applied and reported nowhere.
func ActionKinds() []ActionKind {
	return []ActionKind{
		ActionCreate, ActionExtend, ActionUpdate, ActionClose,
		ActionNoteStale, ActionNoteDone, ActionHold, ActionSkip,
	}
}

// Action is one reconciliation step.
type Action struct {
	Kind ActionKind
	// Draft is set for ActionCreate.
	Draft Draft
	// TicketKey is set for every action against an existing ticket.
	TicketKey string
	// Images is the set an action concerns: the images to add for ActionExtend.
	Images []string
	// Message is the comment to post, for the note actions.
	Message string
	// Unworked marks a close on a ticket nobody picked up: unassigned and never
	// started. It decides which transition may be used — see
	// CloseTransitionUnworked — because "not done" is an accurate record of a
	// ticket that was never actioned and a false one of a ticket someone worked.
	Unworked bool
	// NoLongerActionable marks a close made because the work stopped mattering
	// rather than because it was done, so the writer uses that transition and the
	// history records the reason.
	NoLongerActionable bool
	// Reason is the machine-readable cause of a close or done-note: upgrade-landed,
	// not-running, no-longer-actionable, upgrade-clears-nothing.
	Reason string
	// Dedupe identifies a comment's content so it is posted once rather than on
	// every run. Empty means "always post".
	//
	// Reconciliation is a loop: without this, a ticket sitting in a state that
	// warrants a note collects an identical comment every refresh — hourly,
	// indefinitely — which buries the ticket's real history and trains people to
	// ignore anything patchwright says. The key includes the facts that would make
	// a fresh comment worth reading, so a note whose content has genuinely changed
	// still gets posted.
	Dedupe string
	// Why explains the action in the dry run and the logs.
	Why string
}

// ReconcileInput is everything a decision needs: what should be ticketed, what
// tickets exist, and the findings behind them.
type ReconcileInput struct {
	Drafts []Draft
	// OpenByImage maps an image repository to the open tickets covering it.
	OpenByImage map[string][]Existing
	// Findings are all findings from the assessment, used to tell "fixed" from
	// "no longer assessed" when a ticket's work looks finished.
	Findings []sink.FindingView
	// Skipped is what the planner declined to ticket, and why. Reconciliation needs
	// it to tell a finding that was fixed from one that configuration chose not to
	// track: both are absent from Drafts, and only the first means anything is
	// finished.
	Skipped []Skip
	// Config decides whether a ticket may be closed, resolved per project so a
	// route can enable closing for its own board without enabling it everywhere.
	// The zero value closes nothing, which is the safe default for a caller that
	// has not thought about it.
	Config config.JiraConfig
	// RecentlyReported are repositories that left the queue this run or a run or two
	// ago and that the history record has not yet given up on: absent from the
	// assessment, no longer running, or no longer matching a rule. A ticket for one
	// is held rather than closed or commented on. A provider that drops an image
	// from one response and returns it in the next has not lost coverage, and a
	// preview workload that scales to nothing for an hour has not been switched off.
	// Once the history lapses the item the repository leaves this set, and the
	// close follows on that run.
	RecentlyReported map[string]bool
}

// Reconcile turns the difference between drafts and open tickets into actions.
func Reconcile(in ReconcileInput) []Action {
	var actions []Action
	claimed := map[string]bool{} // tickets accounted for by a draft

	for _, d := range in.Drafts {
		covered, uncovered, tickets := split(d.Images, in.OpenByImage)
		if len(tickets) == 0 {
			actions = append(actions, Action{
				Kind: ActionCreate, Draft: d,
				Why: "no open ticket covers any of its images",
			})
			continue
		}
		for _, t := range tickets {
			claimed[t.Key] = true
		}
		lead := tickets[0]

		if len(uncovered) > 0 {
			// The nats case: one ticket covered one of three images, so the other
			// two were never raised. Extending the ticket matches reality, since
			// they are one change.
			actions = append(actions, Action{
				Kind: ActionExtend, TicketKey: lead.Key, Images: uncovered,
				Message: extendComment(d, covered, uncovered),
				Why: fmt.Sprintf("covers %d of %d images in this change",
					len(covered), len(d.Images)),
			})
			continue
		}
		if stale := staleTarget(d, lead); stale != "" {
			// Untouched means nobody has engaged with it, so correcting it in place
			// is strictly better than leaving a wrong summary with a correction
			// underneath. Once someone has claimed it or started it, editing would
			// change the task after they read it, and a comment is the honest move.
			if lead.Untouched() {
				actions = append(actions, Action{
					Kind: ActionUpdate, TicketKey: lead.Key, Draft: d,
					Why: "the available version has moved on and nobody has picked the ticket up, " +
						"so it was corrected rather than commented on",
				})
				continue
			}
			actions = append(actions, Action{
				Kind: ActionNoteStale, TicketKey: lead.Key, Message: stale,
				// Keyed on the version now available: the target moving again is
				// news worth a second comment, the same target is not.
				Dedupe: "note-stale:" + latestOf(d),
				Why: "the available version has moved on since the ticket was raised, " +
					"and someone has already picked it up so it was not edited",
			})
			continue
		}
		actions = append(actions, Action{
			Kind: ActionSkip, TicketKey: lead.Key,
			Why: "already covers this change",
		})
	}

	actions = append(actions, doneActions(in, claimed)...)
	return actions
}

// doneActions flags open tickets that no draft accounts for any more.
//
// Guarded deliberately: a ticket's images can drop out of the queue because the
// upgrade landed, or because the provider stopped assessing them and the scanner
// did not look either. The second is a coverage loss, and treating it as success
// would retire real work, so it is reported as a coverage problem instead.
func doneActions(in ReconcileInput, claimed map[string]bool) []Action {
	byImage := map[string]sink.FindingView{}
	for _, f := range in.Findings {
		byImage[f.Repository] = f
	}

	seen := map[string]bool{}
	var out []Action
	for _, tickets := range in.OpenByImage {
		for _, t := range tickets {
			if claimed[t.Key] || seen[t.Key] {
				continue
			}
			seen[t.Key] = true

			images := imagesOfTicket(in.OpenByImage, t.Key)

			// The one case where closing is defensible: not "the finding went
			// away" but "the images are still here, we checked, and they are all
			// on the latest version already". Someone merged the Renovate PR and
			// rolled it out without ever seeing the ticket.
			if in.Config.ForProject(projectOf(t.Key)).AutoClose {
				if done, evidence := upgradeComplete(images, byRepo(in.Findings)); done {
					// Whether anyone picked the ticket up decides which transition may
					// be used, so the plan has to carry it: the writer cannot ask Jira
					// after the fact without a second round trip, and the answer would
					// be the same one already in hand.
					unworked := t.Untouched()
					out = append(out, Action{
						Kind: ActionClose, TicketKey: t.Key, Unworked: unworked, Reason: ReasonUpgradeLanded,
						Message: closeComment(evidence, unworked),
						Why:     closeWhy(unworked),
					})
					continue
				}
			}

			// Still actionable, but the change the ticket asks for was measured to fix
			// none of what made it so. Asked before the policy and coverage checks
			// because it is a verdict on the ticket itself: it should not exist, and
			// leaving it open has somebody do work that changes nothing.
			if clearsNothing(images, in.Skipped) {
				out = append(out, clearsNothingAction(t, in.Config.ForProject(projectOf(t.Key))))
				continue
			}

			// Configuration deciding not to ticket something is not the work being
			// done. Without this, raising a priority threshold marks every ticket it
			// newly excludes as finished — observed on a real board, where tickets
			// created that morning were reported done that afternoon.
			if held := policySkipped(images, in.Skipped); len(held) > 0 {
				out = append(out, Action{
					Kind: ActionHold, TicketKey: t.Key,
					Why: "still outstanding, but configuration no longer raises tickets for it: " +
						strings.Join(held, "; "),
				})
				continue
			}
			// Before concluding anything: could we even check? An image whose
			// available version could not be resolved has dropped out of the queue
			// for want of data, not because the work is finished, and saying
			// otherwise on a ticket someone is waiting on is worse than silence.
			if unproven := unprovenImages(images, byImage); len(unproven) > 0 {
				out = append(out, Action{
					Kind: ActionHold, TicketKey: t.Key,
					Why: "cannot tell whether this is done: no available version could be " +
						"resolved for " + strings.Join(unproven, ", "),
				})
				continue
			}
			if recent := recentlyReported(images, in.RecentlyReported); len(recent) > 0 {
				out = append(out, Action{
					Kind: ActionHold, TicketKey: t.Key,
					Why: "left the queue within the last few assessments; waiting to see whether it " +
						"comes back before concluding anything: " + strings.Join(recent, ", "),
				})
				continue
			}
			if blind := unknownImages(images, byImage); len(blind) > 0 {
				out = append(out, Action{
					Kind: ActionNoteDone, TicketKey: t.Key,
					Message: "patchwright no longer reports work for this ticket, but it cannot " +
						"tell whether that is because the upgrade landed or because nothing is " +
						"assessing these images any more: " + strings.Join(blind, ", ") +
						". Worth confirming before closing.",
					// Keyed on which images are blind: a different set is a
					// different problem and worth saying again.
					Dedupe: "note-done:blind:" + strings.Join(blind, ","),
					Why:    "no longer in the queue, but coverage for its images is missing",
				})
				continue
			}
			// From here the images are all still assessed and none is actionable, but
			// the upgrade is not proven to have landed. Why it left the queue decides
			// what to say: switched off everywhere, or no rule asking any more.
			reason, detail := noLongerActionable(images, byRepo(in.Findings))
			if in.Config.ForProject(projectOf(t.Key)).CloseTransitionNoLongerActionable != "" && t.Untouched() {
				out = append(out, Action{
					Kind: ActionClose, TicketKey: t.Key, Unworked: true, NoLongerActionable: true, Reason: reason,
					Message: noLongerActionableComment(reason, detail),
					Why:     noLongerActionableWhy(reason),
				})
				continue
			}
			out = append(out, Action{
				Kind: ActionNoteDone, TicketKey: t.Key, Reason: reason,
				Message: "patchwright no longer reports work for this ticket: " + detail +
					" Left open deliberately: closing is a human decision.",
				// Keyed on the reason, so a ticket that stops being not-running and
				// becomes not-actionable is told why again.
				Dedupe: "note-done:" + reason,
				Why:    noLongerActionableWhy(reason),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TicketKey < out[j].TicketKey })
	return out
}

// Reasons a ticket's work stopped being asked for. Carried on the action so the
// comment, the plan and the history all say the same thing.
const (
	ReasonUpgradeLanded      = "upgrade-landed"
	ReasonNotRunning         = "not-running"
	ReasonNoLongerActionable = "no-longer-actionable"
	// ReasonUpgradeClearsNothing is a ticket whose proposed upgrade was measured to
	// clear none of the vulnerabilities that raised it.
	ReasonUpgradeClearsNothing = "upgrade-clears-nothing"
)

// clearsNothing reports that every one of a ticket's images was skipped because
// the change on offer clears nothing. All of them, not any: a ticket with one image
// the planner said nothing about is not one this can speak for.
func clearsNothing(images []string, skips []Skip) bool {
	if len(images) == 0 {
		return false
	}
	skipped := map[string]bool{}
	for _, s := range skips {
		if s.ClearsNothing {
			skipped[s.Image] = true
		}
	}
	for _, img := range images {
		if !skipped[img] {
			return false
		}
	}
	return true
}

// clearsNothingAction closes a ticket whose upgrade fixes nothing, through the same
// door as any other ticket that stopped mattering: closed as not-done when nobody
// picked it up and the board has a transition for that, commented on otherwise.
func clearsNothingAction(t Existing, cfg config.JiraConfig) Action {
	const why = "still actionable, but the proposed upgrade clears none of the vulnerabilities that raised it"
	detail := "The proposed upgrade does not clear any of the vulnerabilities that raised this ticket: " +
		"patchwright checked the version it asks for, and every image it would deploy still carries them. " +
		"The images stay in the queue, and a new ticket will be raised if an upgrade that clears them " +
		"becomes available."
	if cfg.CloseTransitionNoLongerActionable != "" && t.Untouched() {
		return Action{
			Kind: ActionClose, TicketKey: t.Key, Unworked: true, NoLongerActionable: true,
			Reason: ReasonUpgradeClearsNothing,
			Message: "Closing as not done: the upgrade this ticket asks for does not fix what raised it.\n\n" + detail +
				"\n\nNobody had picked this ticket up, so it is being closed as not-worked rather than as " +
				"completed work, which is the accurate record. Reopen if this is wrong.",
			Why: why + "; nobody picked the ticket up",
		}
	}
	return Action{
		Kind: ActionNoteDone, TicketKey: t.Key, Reason: ReasonUpgradeClearsNothing,
		Message: detail + " Left open deliberately: closing is a human decision.",
		Dedupe:  "note-done:" + ReasonUpgradeClearsNothing,
		Why:     why,
	}
}

// noLongerActionable says why a ticket's images left the queue without the upgrade
// being proven to have landed. Not running wins only when every workload has gone
// and liveness was reconciled for all of them: the vulnerabilities are still in the
// image, nothing is running it. Otherwise something is live, or liveness is unknown,
// and no rule asks for it, which is the risk having gone by another route.
func noLongerActionable(images []string, byRepo map[string][]sink.FindingView) (reason, detail string) {
	allGone := true
	for _, img := range images {
		for _, f := range byRepo[img] {
			if f.Liveness == nil || f.Liveness.Live {
				allGone = false
			}
		}
	}
	list := strings.Join(images, ", ")
	if allGone {
		return ReasonNotRunning, "no workload is running " + list + " in any cluster. The vulnerabilities " +
			"are still in the image; if it is deployed again a new ticket will be raised."
	}
	return ReasonNoLongerActionable, "no policy rule asks for anything on " + list + " any more. The " +
		"vulnerabilities that raised this ticket are gone from what is running; a newer version may still " +
		"exist, but nothing requires it."
}

func noLongerActionableComment(reason, detail string) string {
	head := "Closing as not done: the work this ticket asked for is no longer required by policy."
	if reason == ReasonNotRunning {
		head = "Closing as not done: the image this ticket covers is no longer running anywhere."
	}
	return head + "\n\n" + detail + "\n\nNobody had picked this ticket up, so it is being closed as " +
		"not-worked rather than as completed work, which is the accurate record. Checked, not assumed: " +
		"patchwright never closes a ticket because a finding merely disappeared. Reopen if this is wrong."
}

func noLongerActionableWhy(reason string) string {
	if reason == ReasonNotRunning {
		return "no longer in the queue: nothing is running its images anywhere"
	}
	return "no longer in the queue: no rule asks for its images any more"
}

// latestOf reports the version a single-image draft asks for, used to key a
// staleness note. Empty for grouped drafts, which staleTarget never produces.
func latestOf(d Draft) string {
	if len(d.Upgrades) == 1 {
		_, to := d.Upgrades[0].move()
		return to
	}
	return ""
}

// projectOf extracts the project key from a Jira issue key ("PROJ-123" -> "PROJ").
func projectOf(key string) string {
	project, _, _ := strings.Cut(key, "-")
	return project
}

// closeComment explains a closure, and says plainly when the work landed without the
// ticket being picked up — otherwise a ticket closed as "not done" reads as a
// decision to skip the work rather than a record that it happened anyway.
func closeComment(evidence string, unworked bool) string {
	body := "Closing: already on the latest available version. " + evidence
	if unworked {
		body += "\n\nNobody picked this ticket up, so the upgrade landed by another route — a " +
			"dependency bot, or a release that included it. It is being closed as not-worked " +
			"rather than as completed work, which is the accurate record."
	}
	body += "\n\nChecked, not assumed — patchwright never closes a ticket because a finding " +
		"disappeared. Reopen if this is wrong."
	return body
}

func closeWhy(unworked bool) string {
	if unworked {
		return "every image it covers is already on the latest available version, and nobody picked the ticket up"
	}
	return "every image it covers is already on the latest available version"
}

// byRepo groups findings by repository, since a ticket's images are bare
// repositories and one repository can have several findings — different tags,
// different owners, different clusters. All of them have to be on the latest
// version before the work is finished.
func byRepo(findings []sink.FindingView) map[string][]sink.FindingView {
	out := map[string][]sink.FindingView{}
	for _, f := range findings {
		out[f.Repository] = append(out[f.Repository], f)
	}
	return out
}

// upgradeComplete reports whether every image on a ticket is demonstrably already
// on its latest available version, and the evidence for saying so.
//
// Every condition here is a guard against closing something that is not done:
//
//   - the repository must still be reported, or this is the absent-data case and
//     nothing can be concluded,
//   - remediation must have been checked, or "no upgrade available" only means
//     nobody looked,
//   - the versions must have resolved, or "on the latest" is unproven — a private
//     registry whose tags cannot be listed reports exactly this,
//   - no finding for the repository may still have an upgrade available, which is
//     what catches an old tag still running somewhere,
//   - liveness must have been reconciled, so "everywhere" is a checked claim about
//     running workloads rather than an assumption about the whole estate.
func upgradeComplete(images []string, byRepo map[string][]sink.FindingView) (bool, string) {
	if len(images) == 0 {
		return false, ""
	}
	var evidence []string
	for _, img := range images {
		found := byRepo[img]
		if len(found) == 0 {
			return false, ""
		}
		for _, f := range found {
			if !f.RemediationChecked || f.Upgrade == nil || !f.Upgrade.Resolved {
				return false, ""
			}
			if f.Upgrade.Available {
				return false, ""
			}
			if f.Liveness == nil {
				return false, ""
			}
		}
		evidence = append(evidence, fmt.Sprintf("%s is on %s", img, currentOf(found)))
	}
	sort.Strings(evidence)
	return true, strings.Join(evidence, "; ") + "."
}

// currentOf describes the version(s) a repository is running, so the closing
// comment states what was observed rather than only asserting a conclusion.
func currentOf(findings []sink.FindingView) string {
	seen := map[string]bool{}
	var versions []string
	for _, f := range findings {
		v := f.Tag
		if f.Upgrade != nil && f.Upgrade.Current != "" {
			v = f.Upgrade.Current
		}
		if v != "" && !seen[v] {
			seen[v] = true
			versions = append(versions, v)
		}
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		return "its latest available version"
	}
	return strings.Join(versions, ", ")
}

// imagesOfTicket returns every image the index associates with a ticket.
func imagesOfTicket(index map[string][]Existing, key string) []string {
	var out []string
	for image, tickets := range index {
		for _, t := range tickets {
			if t.Key == key {
				out = append(out, image)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// unknownImages returns the images nothing currently has data for: absent from the
// assessment entirely, or present but never assessed and never scanned.
func unknownImages(images []string, byImage map[string]sink.FindingView) []string {
	var blind []string
	for _, img := range images {
		f, ok := byImage[img]
		if !ok {
			blind = append(blind, img+" (not in the assessment)")
			continue
		}
		if !f.ProviderAssessed && !f.Scanned {
			blind = append(blind, img+" (never assessed or scanned)")
		}
	}
	return blind
}

// policySkipped returns the reasons configuration declined to ticket this ticket's
// images, if it did.
// recentlyReported lists a ticket's images that left the queue inside the
// history's grace period, whether or not the assessment still reports them.
func recentlyReported(images []string, recent map[string]bool) []string {
	var out []string
	for _, img := range images {
		if recent[img] {
			out = append(out, img)
		}
	}
	return out
}

func policySkipped(images []string, skips []Skip) []string {
	byImage := map[string]string{}
	for _, s := range skips {
		if s.Policy {
			byImage[s.Image] = s.Reason
		}
	}
	var out []string
	for _, img := range images {
		if reason, ok := byImage[img]; ok {
			out = append(out, img+" ("+reason+")")
		}
	}
	return out
}

// unprovenImages returns the ticket's images whose remediation state cannot support a
// conclusion either way, with the reason.
//
// This is the difference between "there is no newer version" and "we could not find
// out". Both leave a finding out of the queue, so both make a ticket look unaccounted
// for, and only the first means the work is done. An unreadable registry otherwise
// turns every ticket it touches into a false "looks finished".
func unprovenImages(images []string, byImage map[string]sink.FindingView) []string {
	var out []string
	for _, img := range images {
		f, ok := byImage[img]
		if !ok {
			continue // absent entirely: handled as a coverage gap by unknownImages
		}
		if !f.Actionable {
			// The finding no longer asks for anything, so it left the queue because the
			// work is done — whatever the remediation state. This is the case the
			// note-done comment exists for.
			continue
		}
		// Still actionable, yet nothing was raised for it: the only reason is that no
		// upgrade could be established, which is not the same as there being none.
		switch {
		case !f.RemediationChecked:
			out = append(out, img+" (upgrade detection did not run)")
		case f.Upgrade == nil:
			out = append(out, img+" (no upgrade information)")
		case !f.Upgrade.Resolved:
			reason := f.Upgrade.Reason
			if reason == "" {
				reason = "no reason given"
			}
			out = append(out, img+" ("+reason+")")
		}
	}
	return out
}

// split partitions a draft's images by whether an open ticket covers them.
func split(images []string, index map[string][]Existing) (covered, uncovered []string, tickets []Existing) {
	seen := map[string]bool{}
	for _, img := range images {
		found := index[img]
		if len(found) == 0 {
			uncovered = append(uncovered, img)
			continue
		}
		covered = append(covered, img)
		for _, t := range found {
			if !seen[t.Key] {
				seen[t.Key] = true
				tickets = append(tickets, t)
			}
		}
	}
	return covered, uncovered, tickets
}

// staleTarget reports a comment when the ticket's summary names a version that is
// no longer the one available. Only attempted for a single-image draft whose
// summary we generated, so the version in it is ours to parse rather than guessed
// from someone's prose.
func staleTarget(d Draft, t Existing) string {
	if len(d.Images) != 1 || len(d.Upgrades) != 1 || t.Summary == "" {
		return ""
	}
	_, latest := d.Upgrades[0].move()
	if latest == "" {
		return ""
	}
	const marker = " to "
	i := strings.LastIndex(t.Summary, marker)
	if i < 0 {
		return ""
	}
	was := strings.TrimSpace(t.Summary[i+len(marker):])
	if was == "" || was == latest || strings.EqualFold(was, "the latest version") {
		return ""
	}
	return fmt.Sprintf("The available version has moved on since this was raised: "+
		"%s is now at %s, not %s. The upgrade target has changed; the ticket has not "+
		"been edited.", d.Images[0], latest, was)
}

func extendComment(d Draft, covered, uncovered []string) string {
	return fmt.Sprintf("Adding %s to this ticket.\n\nThese images are upgraded by the same "+
		"change as %s, so they belong here rather than in tickets of their own. While this "+
		"ticket was open they had no ticket at all, because an open ticket on any image in a "+
		"change suppresses the rest.\n\nThe change now covers: %s",
		strings.Join(uncovered, ", "), strings.Join(covered, ", "),
		strings.Join(append(append([]string{}, covered...), uncovered...), ", "))
}
