package kube

import (
	"reflect"
	"testing"
)

func TestClusterLabels(t *testing.T) {
	cases := []struct {
		name string
		src  *Source
		want []string
	}{
		{name: "current context by default", src: &Source{}, want: []string{"current-context"}},
		{name: "named contexts, sorted", src: &Source{contexts: []string{"b", "a"}}, want: []string{"a", "b"}},
		{name: "in cluster only", src: &Source{inCluster: true}, want: []string{"in-cluster"}},
		{name: "in cluster and contexts", src: &Source{inCluster: true, contexts: []string{"remote"}}, want: []string{"in-cluster", "remote"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.src.ClusterLabels(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("labels = %v, want %v", got, c.want)
			}
		})
	}
}
