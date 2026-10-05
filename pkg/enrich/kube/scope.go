package kube

import "sort"

// ClusterLabels names the clusters this source is configured to read, labelled as
// its reads and failures label them, without connecting to any. The history record
// compares it across runs: a cluster taken out of the source makes every image on it
// look switched off, and that is no failure for anything else to notice.
func (s *Source) ClusterLabels() []string {
	var out []string
	if s.inCluster {
		out = append(out, "in-cluster")
	}
	if len(s.contexts) > 0 || s.kubeconfig != "" || !s.inCluster {
		if len(s.contexts) == 0 {
			out = append(out, "current-context")
		}
		out = append(out, s.contexts...)
	}
	sort.Strings(out)
	return out
}
