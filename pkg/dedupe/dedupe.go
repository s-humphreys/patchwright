// Package dedupe collapses the many raw occurrences of an image into a single
// assessed image. This is patchwright's primary noise reducer: the same image
// commonly runs in dozens of places, and it only needs to be assessed — and
// remediated — once.
package dedupe

import "github.com/s-humphreys/patchwright/pkg/model"

// ByImage groups occurrences by image (digest when known, otherwise full
// reference) into AssessedImages. Representative counts are the maximum seen
// per severity across occurrences (scans can disagree slightly; the worst case
// is the safe one), risk score is the maximum, and per-CVE vulnerabilities are
// unioned by ID. Output order follows first appearance in the input, so the
// result is deterministic for a given input.
func ByImage(occurrences []model.Occurrence) []model.AssessedImage {
	index := map[string]*model.AssessedImage{}
	seenVuln := map[string]map[string]struct{}{} // image key -> set of CVE IDs
	var order []string

	for _, o := range occurrences {
		key := o.Image.Key()
		ai := index[key]
		if ai == nil {
			ai = &model.AssessedImage{Image: o.Image, Counts: model.Counts{}}
			index[key] = ai
			seenVuln[key] = map[string]struct{}{}
			order = append(order, key)
		}

		ai.Occurrences = append(ai.Occurrences, o)

		for sev, n := range o.Counts {
			if n > ai.Counts[sev] {
				ai.Counts[sev] = n
			}
		}
		if o.RiskScore > ai.RiskScore {
			ai.RiskScore = o.RiskScore
		}
		for _, v := range o.Vulns {
			if _, ok := seenVuln[key][v.ID]; ok {
				continue
			}
			seenVuln[key][v.ID] = struct{}{}
			ai.Vulns = append(ai.Vulns, v)
		}
	}

	out := make([]model.AssessedImage, 0, len(order))
	for _, key := range order {
		out = append(out, *index[key])
	}
	return out
}
