package upgrade

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/support"
)

// End-of-life bases, and the only upgrade that helps once a line is dead.
//
// An image on a maintained line and an image on a dead one both report "no upgrade
// available", and they mean opposite things. The first is current. The second will never
// receive another fix: its tag will not move again, so every CVE published against it
// from now on is permanent. The queue rendered both as an empty Fix column, which reads
// as nothing-to-do on the more urgent of the two.
//
// What this adds is the move that actually exists — off the line, not along it — and it
// deliberately does not reach for the newest thing available. The newest major of a
// runtime is frequently one nobody should adopt: when Node 20 died the registry held 22,
// 24 and 26, and 26 was Current with its LTS promotion still months away. Recommending
// it would have produced advice a team is right to ignore, which is worse than no advice
// because it spends credibility. So the recommendation is the newest line that is both
// maintained and already LTS, with the nearest supported line offered alongside it: one
// buys the longest runway, the other is the smallest change that stops the bleeding, and
// choosing between them is the team's call, not this tool's.

// supportStatus looks up the maintenance status of the line a base image sits on.
//
// A nil return means not checked, which the model and the page keep distinct from
// supported. Every failure path here returns nil rather than a verdict: an unrecognised
// repository, an unreachable feed and a product with no matching cycle are all "we do
// not know", and stating any of them as "maintained" would be a lie the queue then acts
// on.
func (r *BaseResolver) supportStatus(ctx context.Context, base model.Image, now time.Time) *model.Support {
	if r.Support == nil {
		return nil
	}
	product, ok := support.ProductFor(base.Registry+"/"+base.Repository, r.Cfg.SupportProducts)
	if !ok {
		return nil
	}
	prod, err := r.Support.Product(ctx, product)
	if err != nil {
		// Logged, not returned: one unreachable product must not fail an assessment,
		// and the absence is already visible as an unchecked status.
		slog.DebugContext(ctx, "support windows unavailable", "product", product, "error", err)
		return nil
	}
	cycle, found := prod.Cycle(base.Tag)
	if !found {
		return nil
	}
	supported, known := cycle.Supported(now)
	st := &model.Support{
		Product:   product,
		Cycle:     cycle.Name,
		Supported: supported,
		Known:     known,
		Source:    r.Support.Name(),
	}
	if cycle.EOLKnown {
		st.EOL = cycle.EOL.Format("2006-01-02")
	}
	if adoptable, newest, ok := prod.Adoptable(now); ok {
		st.Recommended, st.Newest = adoptable.Name, newest.Name
	} else {
		st.Newest = ""
	}
	if nearest, ok := prod.Nearest(now, cycle.Name); ok {
		st.Nearest = nearest.Name
	}
	// Only worth naming separately when they differ; equal values are noise that
	// invites the reader to look for a distinction that is not there.
	if st.Nearest == st.Recommended {
		st.Nearest = ""
	}
	if st.Newest == st.Recommended {
		st.Newest = ""
	}
	return st
}

// offTrackUpgrade names the move off a dead line, when one exists and the registry has it.
//
// The tag is built by substituting the cycle into the tag the image already uses, so
// "20-alpine" becomes "24-alpine" and the variant is preserved: recommending "24" would
// silently swap Alpine for Debian, which is the same mistake newestInTrack's suffix rule
// exists to prevent.
//
// The candidate is then VERIFIED against the registry rather than assumed. A constructed
// tag that does not exist would send somebody to a 404, and "there is a fix, here it is,
// it is not real" is worse than reporting no fix at all.
func (r *BaseResolver) offTrackUpgrade(ctx context.Context, base model.Image, up model.Upgrade) model.Upgrade {
	st := up.Support
	if st == nil || !st.Known || st.Supported || st.Recommended == "" {
		return up
	}
	tags, err := r.Lister.Tags(ctx, base.Registry+"/"+base.Repository)
	if err != nil {
		// The status still stands: the line is dead whether or not a target can be
		// named, and saying so is most of the value.
		return up
	}
	present := map[string]bool{}
	for _, t := range tags {
		present[t] = true
	}
	for _, cycle := range []string{st.Recommended, st.Nearest} {
		if cycle == "" {
			continue
		}
		candidate := substituteCycle(base.Tag, st.Cycle, cycle)
		if candidate == "" || candidate == base.Tag || !present[candidate] {
			continue
		}
		up.Latest = candidate
		up.Available = true
		up.OutOfTrack = true
		return up
	}
	return up
}

// substituteCycle replaces the version part of a tag while keeping its variant suffix.
//
// Only the leading version is touched, and only when the tag actually starts with the
// cycle it claims to: a tag whose shape is not understood is left alone rather than
// mangled into something plausible-looking.
func substituteCycle(tag, from, to string) string {
	if tag == "" || from == "" || to == "" {
		return ""
	}
	if !strings.HasPrefix(tag, from) {
		return ""
	}
	rest := tag[len(from):]
	// The remainder must be a boundary, not more version: "2" must not match the "20"
	// line and produce "24" out of "20.19".
	if rest != "" && !strings.ContainsAny(rest[:1], "-_.") {
		return ""
	}
	// A dotted remainder is a more specific version on the old line ("20.19.5"), and
	// its patch numbers mean nothing on the new one. Drop to the cycle plus variant.
	if strings.HasPrefix(rest, ".") {
		if i := strings.IndexAny(rest, "-_"); i >= 0 {
			rest = rest[i:]
		} else {
			rest = ""
		}
	}
	return to + rest
}
