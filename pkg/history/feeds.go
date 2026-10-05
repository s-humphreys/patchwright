package history

// feedStanding follows an item's standing in KEV and in the EPSS band across the
// events a report reads, so that a move into KEV or a decay out of the band is
// counted once per transition rather than once per changed event.
//
// The events alone overcount. A run whose exploit lookup fails keeps every CVE but
// loses its KEV flags and EPSS scores, so each item drops kev and epss-high and the
// next complete run adds them back: one outage read as an EPSS decay and a fresh
// KEV for every exploited item in the estate. A CVE leaving because it was fixed
// also drops the signal, which is remediation, not decay. So a signal leaving only
// counts as leaving when the CVEs that carried it went with it (KEV) or are still
// there with a lower score (EPSS); one whose CVEs are still there unflagged, or
// unscored, is the feed missing and the item keeps its standing.
type feedStanding struct {
	// known is set once a snapshot of the item has been seen in the range.
	known bool
	kev   bool
	// kevIDs are the CVEs last seen flagged KEV, nil when the item's standing was
	// learnt from a signal alone.
	kevIDs map[string]bool
	epss   bool
	// epssIDs are the CVEs last seen above the EPSS threshold, nil likewise.
	epssIDs map[string]bool
}

type itemRef struct {
	item int64
	key  string
}

type feedStandings map[itemRef]*feedStanding

// observe applies one event and reports whether it moved the item into KEV, or out
// of the EPSS band by decay.
func (fs feedStandings) observe(e Event) (becameKEV, decayed bool) {
	st := fs[itemRef{e.ItemID, e.Key}]
	if st == nil {
		st = &feedStanding{}
		fs[itemRef{e.ItemID, e.Key}] = st
	}
	snap := e.Payload.Snapshot
	switch e.Kind {
	case KindOpened, KindReassigned:
		if snap != nil {
			st.set(*snap)
		}
		return false, false
	case KindChanged:
	default:
		return false, false
	}
	added := func(sig string) bool { return containsString(e.Payload.SignalsAdded, sig) }
	removed := func(sig string) bool { return containsString(e.Payload.SignalsRemoved, sig) }
	if snap == nil {
		// Signals alone, as early records and tests carry them.
		if added(SignalKnownExploit) && !st.kev {
			becameKEV = true
		}
		st.kev = (st.kev || added(SignalKnownExploit)) && !removed(SignalKnownExploit)
		if removed(SignalEPSSHigh) && (st.epss || !st.known) {
			decayed = true
		}
		st.epss = (st.epss || added(SignalEPSSHigh)) && !removed(SignalEPSSHigh)
		return becameKEV, decayed
	}

	// Only a signal leaving needs the CVEs by ID, and most changed events have none
	// leave: built for every one, these maps were a quarter of a report's allocation.
	var byID map[string]CVE
	present := func() map[string]CVE {
		if byID == nil {
			byID = make(map[string]CVE, len(snap.CVEs))
			for _, c := range snap.CVEs {
				byID[c.ID] = c
			}
		}
		return byID
	}
	// A run that missed a source cannot vouch for anything leaving, so the item
	// keeps its standing through it, as through an outage.
	partial := e.Payload.Reason == reasonPartial
	if snap.Has(SignalKnownExploit) {
		becameKEV = !st.kev && (st.known || added(SignalKnownExploit))
		st.kev, st.kevIDs = true, flagged(*snap)
	} else if st.kev || (!st.known && removed(SignalKnownExploit)) {
		switch still := stillPresent(st.kevIDs, present()); {
		case partial:
			st.kev = true
		case st.kevIDs != nil:
			st.kev, st.kevIDs = len(still) > 0, still
		default:
			// Which CVEs were exploited is not known; a removal that took no CVE with
			// it can only be the flag going.
			st.kev = len(e.Payload.CVEsRemoved) == 0
		}
	}

	if snap.Has(SignalEPSSHigh) {
		st.epss, st.epssIDs = true, high(*snap)
	} else if st.epss || (!st.known && removed(SignalEPSSHigh)) {
		if partial {
			st.epss = true
		} else if st.epssIDs != nil {
			still := stillPresent(st.epssIDs, present())
			switch {
			case len(still) == 0:
				st.epss, st.epssIDs = false, nil
			case unscored(still, present()):
				st.epssIDs = still
			default:
				decayed = true
				st.epss, st.epssIDs = false, nil
			}
		} else if len(snap.CVEs) > 0 && unscored(nil, present()) {
			st.epss = true
		} else if len(e.Payload.CVEsRemoved) > 0 {
			// Which CVEs were above the threshold is not known; one leaving with the
			// signal is far likelier the high one fixed than a score falling.
			st.epss = false
		} else {
			decayed = true
			st.epss = false
		}
	}
	st.known = true
	return becameKEV, decayed
}

func (st *feedStanding) set(s Snapshot) {
	st.known = true
	st.kev, st.kevIDs = s.Has(SignalKnownExploit), flagged(s)
	st.epss, st.epssIDs = s.Has(SignalEPSSHigh), high(s)
}

// SignalKnownExploit is the queue's signal for a CVE in CISA KEV.
const SignalKnownExploit = "kev"

func flagged(s Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, c := range s.CVEs {
		if c.KEV {
			out[c.ID] = true
		}
	}
	return out
}

func high(s Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, c := range s.CVEs {
		if c.EPSS > EPSSHigh {
			out[c.ID] = true
		}
	}
	return out
}

func stillPresent(ids map[string]bool, present map[string]CVE) map[string]bool {
	if ids == nil {
		return nil
	}
	out := map[string]bool{}
	for id := range ids {
		if _, ok := present[id]; ok {
			out[id] = true
		}
	}
	return out
}

// unscored reports that none of ids (every CVE present, when ids is nil) has an
// EPSS score: the feed did not answer, since every published CVE has one.
func unscored(ids map[string]bool, present map[string]CVE) bool {
	for id, c := range present {
		if (ids == nil || ids[id]) && c.EPSS > 0 {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
