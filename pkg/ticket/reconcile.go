package ticket

import (
	"fmt"
	"sort"
	"strings"

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
	// ActionSkip records a ticket that already covers its group correctly.
	ActionSkip ActionKind = "skip"
)

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
	// AutoClose allows closing tickets whose work is provably finished. Without
	// it, the same evidence produces a comment.
	AutoClose bool
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
			if in.AutoClose {
				if done, evidence := upgradeComplete(images, byRepo(in.Findings)); done {
					out = append(out, Action{
						Kind: ActionClose, TicketKey: t.Key,
						Message: "patchwright is closing this: every image it covers is still being " +
							"reported, was checked for a newer version, and is already on the latest " +
							"available one. " + evidence + "\n\nThis is a positive check rather than " +
							"an absence of data. Reopen if that is wrong.",
						Why: "every image it covers is already on the latest available version",
					})
					continue
				}
			}

			if blind := unknownImages(images, byImage); len(blind) > 0 {
				out = append(out, Action{
					Kind: ActionNoteDone, TicketKey: t.Key,
					Message: "patchwright no longer reports work for this ticket, but it cannot " +
						"tell whether that is because the upgrade landed or because nothing is " +
						"assessing these images any more: " + strings.Join(blind, ", ") +
						". Worth confirming before closing.",
					Why: "no longer in the queue, but coverage for its images is missing",
				})
				continue
			}
			out = append(out, Action{
				Kind: ActionNoteDone, TicketKey: t.Key,
				Message: "patchwright no longer reports an available upgrade for this ticket's " +
					"images, which suggests the work is done. Left open deliberately: closing " +
					"is a human decision.",
				Why: "no longer in the queue and its images are still assessed",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TicketKey < out[j].TicketKey })
	return out
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
	latest := d.Upgrades[0].Latest
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
