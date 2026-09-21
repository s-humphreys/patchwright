package history

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

var t0 = time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

func view(image, class, team, priority string) sink.FindingView {
	repo := image[:strings.LastIndex(image, ":")]
	return sink.FindingView{
		Image: image, Repository: repo, Tag: strings.TrimPrefix(strings.TrimPrefix(image, repo), ":"),
		Owner:      sink.OwnerView{Class: class, Team: team},
		Actionable: true, Priority: priority, Rule: "any-critical",
		Counts: map[string]int{"critical": 2, "high": 5}, Risk: 700,
		RemediationChecked: true,
		Upgrade:            &sink.UpgradeView{Kind: "helm", Name: "nginx", Current: "1.0", Latest: "1.2", Available: true, Resolved: true},
		Liveness:           &sink.LivenessView{Live: true},
	}
}

func fixed(v sink.FindingView) sink.FindingView {
	v.Actionable = false
	v.Counts = map[string]int{}
	v.Upgrade = &sink.UpgradeView{Kind: "helm", Name: "nginx", Current: "1.2", Latest: "1.2", Available: false, Resolved: true}
	return v
}

func TestSnapshotsGroupByTargetNameNotVersion(t *testing.T) {
	a := view("acr.io/app:1", "eng", "orders", "high")
	b := view("acr.io/app:2", "eng", "orders", "urgent")
	b.Upgrade.Latest = "1.3" // a second deployment sees a newer release; same item
	b.Signals = []string{"kev", "in-flight"}
	b.TopEPSS = 0.7
	b.FixableCritical = 1
	other := view("acr.io/app:2", "eng", "billing", "low")
	suppressed := view("acr.io/lib:1", "eng", "orders", "low")
	suppressed.Suppressed = true

	got := Snapshots([]sink.FindingView{a, b, other, suppressed}, map[string][]string{"acr.io/app": {"DVOP-1"}})
	if len(got) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(got), got)
	}
	orders := got[1]
	if orders.Key != Key("eng", "orders", "acr.io/app", "nginx") {
		t.Errorf("key = %q", orders.Key)
	}
	if orders.Priority != "urgent" || orders.TargetVersion != "1.3" {
		t.Errorf("lead should be the urgent deployment: %+v", orders)
	}
	want := []string{"epss-high", "fixable-critical", "kev"}
	if !reflect.DeepEqual(orders.Signals, want) {
		t.Errorf("signals = %v, want %v (transient in-flight dropped, derived ones added)", orders.Signals, want)
	}
	if !reflect.DeepEqual(orders.Tickets, []string{"DVOP-1"}) || !orders.Ticketed() {
		t.Errorf("tickets = %v", orders.Tickets)
	}
	if len(orders.Images) != 2 || orders.Critical != 2 {
		t.Errorf("images/counts wrong: %+v", orders)
	}
}

func openState(id int64, s Snapshot, openedAt time.Time) State {
	return State{ID: id, OpenedAt: openedAt, Opened: s, Current: s}
}

func TestDiffOpensNewItems(t *testing.T) {
	cur := Snapshots([]sink.FindingView{view("acr.io/app:1", "eng", "orders", "high")}, nil)
	events := Diff(Input{Current: cur, Now: t0})
	if len(events) != 1 || events[0].Kind != KindOpened || events[0].Payload.Snapshot == nil {
		t.Fatalf("want one opened event with a snapshot, got %+v", events)
	}
	if events[0].ItemID != 0 {
		t.Errorf("opened events carry no item id yet")
	}
}

func TestDiffRecordsChangesWhileOpen(t *testing.T) {
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, nil)[0]
	v.Priority = "urgent"
	v.Signals = []string{"kev"}
	v.TopEPSS = 0.9
	cur := Snapshots([]sink.FindingView{v}, nil)

	events := Diff(Input{Open: []State{openState(7, prev, t0.AddDate(0, 0, -3))}, Current: cur, Views: []sink.FindingView{v}, Now: t0})
	if len(events) != 1 || events[0].Kind != KindChanged || events[0].ItemID != 7 {
		t.Fatalf("want one changed event for item 7, got %+v", events)
	}
	p := events[0].Payload
	if !reflect.DeepEqual(p.SignalsAdded, []string{"epss-high", "kev"}) {
		t.Errorf("signals added = %v", p.SignalsAdded)
	}
	if len(p.Changes) != 3 || p.Changes[0] != "priority: high -> urgent" {
		t.Errorf("changes = %v", p.Changes)
	}
	if p.Snapshot == nil || p.Snapshot.Priority != "urgent" {
		t.Errorf("changed event should carry the new state")
	}

	// A second identical run is silent.
	again := Diff(Input{Open: []State{openState(7, cur[0], t0)}, Current: cur, Views: []sink.FindingView{v}, Now: t0.Add(time.Hour)})
	if len(again) != 0 {
		t.Errorf("no movement should produce no events, got %+v", again)
	}
}

func TestDiffResolvesWithEvidence(t *testing.T) {
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, map[string][]string{"acr.io/app": {"DVOP-9"}})[0]
	now := fixed(v)
	opened := t0.AddDate(0, 0, -40)

	events := Diff(Input{
		Open: []State{openState(3, prev, opened)}, Current: nil, Views: []sink.FindingView{now},
		OpenTickets: nil, Now: t0,
	})
	if len(events) != 2 {
		t.Fatalf("want resolved + ticket_closed, got %+v", events)
	}
	res := events[0]
	if res.Kind != KindResolved || res.ItemID != 3 {
		t.Fatalf("want resolved for item 3, got %+v", res)
	}
	if res.Payload.Evidence != "acr.io/app is on 1.2." {
		t.Errorf("evidence = %q", res.Payload.Evidence)
	}
	if !res.Payload.Ticketed || res.Payload.DaysOpen == nil || *res.Payload.DaysOpen != 40 {
		t.Errorf("ticketed/days wrong: %+v", res.Payload)
	}
	if res.Payload.Opened == nil || res.Payload.Opened.Key != prev.Key {
		t.Errorf("resolved must carry the opening snapshot for classification")
	}
	tc := events[1]
	if tc.Kind != KindTicketClosed || tc.Payload.Ticket != "DVOP-9" || tc.Payload.EvidenceAtClose == nil || !*tc.Payload.EvidenceAtClose {
		t.Errorf("ticket closed with evidence expected, got %+v", tc)
	}
}

func TestDiffLapsesWithoutEvidence(t *testing.T) {
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, nil)[0]
	st := openState(3, prev, t0.AddDate(0, 0, -5))

	cases := []struct {
		name   string
		views  []sink.FindingView
		reason string
	}{
		{"not reported", nil, "no longer reported"},
		{"still available", []sink.FindingView{func() sink.FindingView { x := v; x.Actionable = false; return x }()}, "still has 1.2 available"},
		{"not running", []sink.FindingView{func() sink.FindingView { x := fixed(v); x.Liveness = &sink.LivenessView{Live: false}; return x }()}, "no longer running"},
		{"unresolved", []sink.FindingView{func() sink.FindingView { x := fixed(v); x.Upgrade.Resolved = false; return x }()}, "could not be resolved"},
		{"unchecked", []sink.FindingView{func() sink.FindingView { x := fixed(v); x.RemediationChecked = false; return x }()}, "not checked"},
		{"no liveness", []sink.FindingView{func() sink.FindingView { x := fixed(v); x.Liveness = nil; return x }()}, "liveness"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events := Diff(Input{Open: []State{st}, Views: c.views, Now: t0})
			if len(events) != 1 || events[0].Kind != KindLapsed {
				t.Fatalf("want lapsed, got %+v", events)
			}
			if !strings.Contains(events[0].Payload.Reason, c.reason) {
				t.Errorf("reason %q should mention %q", events[0].Payload.Reason, c.reason)
			}
			if events[0].Payload.Evidence != "" {
				t.Errorf("a lapse carries no evidence")
			}
		})
	}
}

func TestDiffReassignsRatherThanClosing(t *testing.T) {
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, nil)[0]
	v.Owner.Team = "payments"
	cur := Snapshots([]sink.FindingView{v}, nil)

	events := Diff(Input{Open: []State{openState(5, prev, t0)}, Current: cur, Views: []sink.FindingView{v}, Now: t0})
	if len(events) != 1 || events[0].Kind != KindReassigned || events[0].ItemID != 5 {
		t.Fatalf("want a single reassigned event, got %+v", events)
	}
	p := events[0].Payload
	if p.From.Team != "orders" || p.To.Team != "payments" || p.Snapshot.Key != cur[0].Key {
		t.Errorf("reassignment payload wrong: %+v", p)
	}
}

func TestTicketEventsAttributeByImage(t *testing.T) {
	a := Snapshots([]sink.FindingView{view("acr.io/app:1", "eng", "orders", "high")}, nil)[0]
	b := Snapshots([]sink.FindingView{view("acr.io/other:1", "eng", "orders", "high")}, nil)[0]
	open := []State{openState(1, a, t0), openState(2, b, t0)}
	events := TicketEvents(open, []TicketWrite{{Key: "DVOP-1", Action: "create", Images: []string{"acr.io/app:1"}}}, t0)
	if len(events) != 1 || events[0].ItemID != 1 || events[0].Payload.Ticket != "DVOP-1" {
		t.Fatalf("want one ticket_raised on item 1, got %+v", events)
	}
}

func TestRiskStats(t *testing.T) {
	items := []Snapshot{{Risk: 10}, {Risk: 30, Priority: "urgent", Signals: []string{"kev"}}, {Risk: 20}}
	r := Risk(items)
	if r.Items != 3 || r.Sum != 60 || r.Max != 30 || r.P50 != 20 || r.Urgent != 1 || r.KnownExploited != 1 {
		t.Errorf("risk = %+v", r)
	}
	if Risk(nil).Items != 0 {
		t.Errorf("empty set is zero, not a panic")
	}
}
