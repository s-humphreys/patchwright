package history

import (
	"reflect"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Decommissions decides the same from events cut down by DecommissionEvent as from
// whole ones, so the recorder can hold the lookback without its snapshots.
func TestDecommissionEventKeepsTheVerdict(t *testing.T) {
	since := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	after := 7 * 24 * time.Hour
	now := since.Add(after + time.Hour)
	key := Key("eng", "orders", "acr.io/app", "nginx")
	runs := []Assessment{{FinishedAt: since.Add(-time.Hour), LiveScope: "kube:a"}, {FinishedAt: since.Add(time.Hour), LiveScope: "kube:a"}}
	big := &Snapshot{Key: "noise", Repository: "acr.io/noise", Images: []string{"acr.io/noise:1"}, CVEs: []CVE{{ID: "CVE-1", KEV: true}}}
	noise := []Event{
		{ItemID: 3, Key: "noise", Kind: KindChanged, At: since.Add(time.Hour), Payload: Payload{Snapshot: big, CVEsAdded: []string{"CVE-1"}}},
		{ItemID: 3, Key: "noise", Kind: KindTicketRaised, At: since.Add(2 * time.Hour), Payload: Payload{Ticket: "PROJ-9"}},
	}
	for _, tc := range []struct {
		name  string
		extra []Event
		want  int
	}{
		{name: "credited", want: 1},
		{name: "came back under its key", extra: []Event{{ItemID: 9, Key: key, Kind: KindOpened, At: since.Add(48 * time.Hour),
			Payload: Payload{Snapshot: &Snapshot{Key: key, Repository: "acr.io/app", Images: []string{"acr.io/app:2"}}}}}},
		{name: "its repository changed under another item", extra: []Event{{ItemID: 9, Key: "other", Kind: KindChanged, At: since.Add(48 * time.Hour),
			Payload: Payload{Snapshot: &Snapshot{Key: "other", Repository: "acr.io/app"}}}}},
		{name: "already decommissioned", extra: []Event{{ItemID: 7, Key: key, Kind: KindDecommissioned, At: since}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := append(append([]Event{lapsedNotRunning(t, since)}, noise...), tc.extra...)
			var slim []Event
			for _, e := range events {
				if e, ok := DecommissionEvent(e); ok {
					slim = append(slim, e)
				}
			}
			in := DecommissionInput{After: after, Assessments: runs, Views: []sink.FindingView{}, LiveScope: "kube:a", Now: now}
			full := in
			full.Events = events
			cut := in
			cut.Events = slim
			want, got := Decommissions(full), Decommissions(cut)
			if len(want) != tc.want || !reflect.DeepEqual(got, want) {
				t.Errorf("from cut events %+v, from whole ones %+v (want %d)", got, want, tc.want)
			}
		})
	}

	if _, ok := DecommissionEvent(noise[1]); ok {
		t.Error("a ticket event is not read by Decommissions and should be dropped")
	}
	cut, _ := DecommissionEvent(noise[0])
	if s := cut.Payload.Snapshot; s == nil || !reflect.DeepEqual(*s, Snapshot{Repository: "acr.io/noise"}) || cut.Payload.CVEsAdded != nil {
		t.Errorf("cut changed event = %+v, want only its repository", cut)
	}
}
