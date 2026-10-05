package history

import (
	"fmt"
	"time"
)

// TicketScope is where a route left out of the ticket counts files its tickets: a
// project, and the epic when the route sets one.
type TicketScope struct {
	Route   string
	Project string
	Epic    string
}

// Holds reports whether a ticket is in the scope.
func (s TicketScope) Holds(t TrackerTicket) bool {
	return t.Project == s.Project && (s.Epic == "" || t.Parent == s.Epic)
}

func (s TicketScope) String() string {
	if s.Epic == "" {
		return fmt.Sprintf("%s (project %s)", s.Route, s.Project)
	}
	return fmt.Sprintf("%s (project %s, epic %s)", s.Route, s.Project, s.Epic)
}

// ExcludedTickets says what configuration left out of the ticket counts. The
// tickets are still raised, reconciled and closed; only the counts drop them.
type ExcludedTickets struct {
	// Routes names each excluded route with its project and epic.
	Routes []string `json:"routes"`
	// Tickets is the distinct excluded tickets created or resolved in the range.
	Tickets int `json:"tickets"`
	// TicketsRaised and TicketsClosed are what tickets_raised and tickets_closed
	// would have counted for them over the range; the Tracker pair the same for the
	// tracker's own counts.
	TicketsRaised        int `json:"tickets_raised"`
	TicketsClosed        int `json:"tickets_closed"`
	TrackerTicketsRaised int `json:"tracker_tickets_raised"`
	TrackerTicketsClosed int `json:"tracker_tickets_closed"`
}

// ExcludeTickets drops the tickets in scopes from what the ticket counts read: the
// record's ticket events, matched by issue key, and the tracker's tickets. tickets
// must hold every ticket an event in the range can name, so a ticket raised before
// the range and extended in it is still recognised. Nil when no scope is set.
func ExcludeTickets(r Range, events []Event, tickets []TrackerTicket, scopes []TicketScope) ([]Event, []TrackerTicket, *ExcludedTickets) {
	if len(scopes) == 0 {
		return events, tickets, nil
	}
	out := &ExcludedTickets{Routes: make([]string, 0, len(scopes))}
	for _, s := range scopes {
		out.Routes = append(out.Routes, s.String())
	}
	from := r.Since
	if p := Periods(r); len(p) > 0 {
		from = p[0].Start
	}
	in := func(t time.Time) bool { return !t.Before(from) && t.Before(r.Until) }

	excluded := map[string]bool{}
	keptTickets := make([]TrackerTicket, 0, len(tickets))
	for _, t := range tickets {
		if !InAnyScope(t, scopes) {
			keptTickets = append(keptTickets, t)
			continue
		}
		excluded[t.Key] = true
		created, resolved := in(t.CreatedAt), t.ResolvedAt != nil && in(*t.ResolvedAt)
		if created {
			out.TrackerTicketsRaised++
		}
		if resolved {
			out.TrackerTicketsClosed++
		}
		if created || resolved {
			out.Tickets++
		}
	}
	var keptEvents, dropped []Event
	for _, e := range events {
		if (e.Kind == KindTicketRaised || e.Kind == KindTicketClosed) && excluded[e.Payload.Ticket] {
			dropped = append(dropped, e)
			continue
		}
		e.Payload.Ticketed = ticketedWithout(e, excluded)
		keptEvents = append(keptEvents, e)
	}
	// Counted the way the report counts them, so the two add up to what it showed
	// before the exclusion.
	for _, m := range Aggregate(r, nil, dropped, nil, time.Time{}, r.Until).Movement {
		out.TicketsRaised += m.TicketsRaised
		out.TicketsClosed += m.TicketsClosed
	}
	return keptEvents, keptTickets, out
}

// ticketedWithout is whether a ticket other than an excluded one covered the item an
// event classifies as ticketed or not. A ticket on an excluded route is not
// remediation work, so an item only it covered was not ticketed work either, and
// the ticketed share cannot exceed the tickets the counts keep.
func ticketedWithout(e Event, excluded map[string]bool) bool {
	if !e.Payload.Ticketed || len(excluded) == 0 {
		return e.Payload.Ticketed
	}
	tickets := e.Payload.Tickets
	if (e.Kind == KindResolved || e.Kind == KindLapsed) && e.Payload.Closed != nil {
		tickets = e.Payload.Closed.Tickets
	}
	if len(tickets) == 0 {
		return true
	}
	for _, k := range tickets {
		if !excluded[k] {
			return true
		}
	}
	return false
}

// InAnyScope reports whether a ticket is in any of the scopes.
func InAnyScope(t TrackerTicket, scopes []TicketScope) bool {
	for _, s := range scopes {
		if s.Holds(t) {
			return true
		}
	}
	return false
}
