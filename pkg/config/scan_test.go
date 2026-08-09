package config

import (
	"reflect"
	"testing"
)

func TestEffectiveSkipOwnerClasses(t *testing.T) {
	// Unset -> default.
	if got := (ScanConfig{}).EffectiveSkipOwnerClasses(); !reflect.DeepEqual(got, []string{"cloud-provider"}) {
		t.Errorf("unset: got %v, want [cloud-provider]", got)
	}
	// Explicit empty -> scan everything.
	if got := (ScanConfig{SkipOwnerClasses: []string{}}).EffectiveSkipOwnerClasses(); len(got) != 0 {
		t.Errorf("explicit empty: got %v, want []", got)
	}
	// Explicit -> as given.
	if got := (ScanConfig{SkipOwnerClasses: []string{"managed"}}).EffectiveSkipOwnerClasses(); !reflect.DeepEqual(got, []string{"managed"}) {
		t.Errorf("explicit: got %v, want [managed]", got)
	}
}
