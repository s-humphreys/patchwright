package history

// feedStanding follows an item's standing in KEV and in the EPSS band across the
// events a report reads, so that a move into KEV or a decay out of the band is
// counted once per transition rather than once per changed event.
//
// The events alone overcount, because an item's CVEs and their flags come and go
// with what the run could see, not only with what changed. A run whose vuln source
// could not answer for an image records the item without that image's CVEs, and the
// next run that reaches it adds them back; a run whose exploit lookup failed keeps
// every CVE but loses its KEV flags and EPSS scores. Read as transitions, each such
// run is the item leaving KEV and the next a fresh entry.
//
// So leaving takes the evidence a cleared CVE takes (see Clearance). The CVEs that
// carried a signal count as gone only when the image they were last seen on was
// replaced, both runs scanned by the same source and running; gone any other way,
// the run could not see them and the item keeps its standing. A CVE still there with
// the flag removed, or a lower score, has left the signal, unless the item carries
// no EPSS score at all, which is the exploit feed not answering. A run that missed a
// source vouches for nothing.
type feedStanding struct {
	// known is set once a snapshot of the item has been seen in the range.
	known bool
	kev   bool
	// kevIDs are the CVEs last seen flagged KEV, nil when the item's standing was
	// learnt from a signal alone, and kevSeen what Clearance needs of the snapshot
	// they were last seen on.
	kevIDs  map[string]bool
	kevSeen *Snapshot
	epss    bool
	// epssIDs are the CVEs last seen above the EPSS threshold, nil likewise.
	epssIDs  map[string]bool
	epssSeen *Snapshot
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
	var seen *Snapshot
	seenHere := func() *Snapshot {
		if seen == nil {
			seen = evidenceOf(*snap)
		}
		return seen
	}
	partial := e.Payload.Reason == reasonPartial
	// gone reports whether CVEs missing from this snapshot since seen really left.
	gone := func(seen *Snapshot) bool {
		return seen != nil && withheld(*seen, *snap, 0, partial) == ""
	}

	if snap.Has(SignalKnownExploit) {
		becameKEV = !st.kev && (st.known || added(SignalKnownExploit))
		st.kev, st.kevIDs, st.kevSeen = true, flagged(*snap), seenHere()
	} else if st.kev || (!st.known && removed(SignalKnownExploit)) {
		switch still := stillPresent(st.kevIDs, present()); {
		case partial:
			st.kev = true
		case st.kevIDs != nil:
			switch {
			case len(still) < len(st.kevIDs) && !gone(st.kevSeen):
				st.kev = true
			case len(still) > 0 && unscored(nil, present()):
				st.kev, st.kevIDs = true, still
			default:
				st.kev, st.kevIDs, st.kevSeen = false, nil, nil
			}
		default:
			// Which CVEs were exploited is not known, nor what scanned them: a removal
			// that took CVEs with it may be the run not seeing them, and one that took
			// none is the flag going unless the feed did not answer.
			st.kev = len(e.Payload.CVEsRemoved) > 0 || unscored(nil, present())
		}
	}

	if snap.Has(SignalEPSSHigh) {
		st.epss, st.epssIDs, st.epssSeen = true, high(*snap), seenHere()
	} else if st.epss || (!st.known && removed(SignalEPSSHigh)) {
		if partial {
			st.epss = true
		} else if st.epssIDs != nil {
			still := stillPresent(st.epssIDs, present())
			switch {
			case len(still) < len(st.epssIDs) && !gone(st.epssSeen):
				// Unseen rather than gone: the standing holds.
			case len(still) == 0:
				st.epss, st.epssIDs, st.epssSeen = false, nil, nil
			case unscored(still, present()):
				st.epssIDs = still
			default:
				decayed = true
				st.epss, st.epssIDs, st.epssSeen = false, nil, nil
			}
		} else if len(snap.CVEs) > 0 && unscored(nil, present()) {
			st.epss = true
		} else if len(e.Payload.CVEsRemoved) > 0 {
			// Which CVEs were above the threshold is not known, nor what scanned them;
			// one leaving with the signal is far likelier the high one gone than a
			// score falling, and nothing says it went rather than went unseen.
			st.epss = true
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
	seen := evidenceOf(s)
	st.kev, st.kevIDs, st.kevSeen = s.Has(SignalKnownExploit), flagged(s), seen
	st.epss, st.epssIDs, st.epssSeen = s.Has(SignalEPSSHigh), high(s), seen
}

// evidenceOf keeps what withheld reads of a snapshot, so a standing holds the
// footprint its CVEs were last seen on without the snapshot's CVE list.
func evidenceOf(s Snapshot) *Snapshot {
	return &Snapshot{Accounts: s.Accounts, Namespaces: s.Namespaces, Scan: s.Scan}
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
