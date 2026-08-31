package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewServer builds an MCP server whose tools answer from src.
//
// src is called per tool invocation rather than captured once, so a long-lived
// session answers from the current assessment instead of the one that happened to
// be cached when it connected.
func NewServer(name, version string, src Source) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: name, Version: version}, nil)
	register(s, src)
	return s
}

// Handler is the Streamable HTTP handler to mount at /mcp. It is a normal handler
// so it sits behind whatever middleware wraps the rest of the routes: the MCP
// endpoint must never be an unauthenticated door into data the page gates.
func Handler(name, version string, src Source) http.Handler {
	server := NewServer(name, version, src)
	return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
}

// errNoAssessment is what every tool returns before the first assessment finishes.
// An explicit "not ready" rather than an empty result, which would read as a clean
// estate at exactly the moment nothing is known.
const errNoAssessment = "No assessment has completed yet, so nothing can be reported. " +
	"This is not an empty estate: it is a service that has not finished its first run."

func register(s *sdk.Server, src Source) {
	type noArgs struct{}

	type serviceArgs struct {
		Service string `json:"service" jsonschema:"the service or image repository, e.g. 'topnotch' or 'myregistry.io/apps/topnotch'"`
	}
	type queueArgs struct {
		Team     string `json:"team,omitempty" jsonschema:"only items owned by this team"`
		Priority string `json:"priority,omitempty" jsonschema:"only this priority: urgent, high, medium or low"`
		Exposure string `json:"exposure,omitempty" jsonschema:"only this exposure: public, internal or unknown"`
		Limit    int    `json:"limit,omitempty" jsonschema:"how many items to return (default 25, max 100)"`
	}
	type teamArgs struct {
		Team string `json:"team" jsonschema:"the owning team"`
	}
	type cveArgs struct {
		ID string `json:"id" jsonschema:"the CVE identifier, e.g. CVE-2026-31431"`
	}

	sdk.AddTool(s, &sdk.Tool{
		Name: "estate_summary",
		Description: "The headline for the whole estate: how many services and vulnerabilities, " +
			"how much of it base rebuilds would clear, the biggest wins available, and what nobody " +
			"is acting on. Start here when the question is broad. Reports coverage, so a low count " +
			"is never mistaken for a healthy estate when it is an unexamined one.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, _ noArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		return result(estateSummary(a))
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "service_report",
		Description: "Everything known about one service: where it is deployed, what it carries, " +
			"how old its image is, the upgrade it needs, and - measured by scanning the base image - " +
			"exactly how many of its CVEs that upgrade clears, how many it leaves, what it introduces, " +
			"and which packages the remainder sits in. Use this whenever somebody names a service.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, args serviceArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		r, ok := serviceReport(a, args.Service)
		if !ok {
			msg := fmt.Sprintf("No service matching %q is in this assessment. That means it was not in "+
				"the scan input or is not deployed, NOT that it is free of vulnerabilities. ", args.Service)
			if near := matchService(a, args.Service); len(near) > 0 {
				msg += "Closest names: " + strings.Join(near, ", ") + "."
			}
			return textResult(msg), nil, nil
		}
		return result(r)
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "worst_first",
		Description: "The work queue, worst first: one row per service and upgrade, with why it " +
			"ranks where it does and what the upgrade would clear. Filter by team, priority or " +
			"exposure. Use this for 'what should we do next' and 'what does team X owe'.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, args queueArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		return result(worstFirst(a, args.Team, args.Priority, args.Exposure, args.Limit))
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "team_report",
		Description: "One team's whole position: what they own, how much is urgent or exposed, " +
			"what is already in progress, what their rebuilds would clear, and their top items. " +
			"Distinguishes an open pull request from a stale one nobody merged.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, args teamArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		r, candidates, ok := teamReport(a, args.Team)
		if !ok {
			msg := fmt.Sprintf("No work is attributed to a team matching %q. ", args.Team)
			if len(candidates) > 0 {
				msg += "Teams in this assessment: " + strings.Join(candidates, ", ") +
					". Call list_facets for the full vocabulary with counts."
			} else {
				msg += "No team is attributed anywhere in this assessment, so ownership is " +
					"unresolved rather than this team having nothing outstanding."
			}
			return textResult(msg), nil, nil
		}
		return result(r)
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "list_facets",
		Description: "The vocabulary of this assessment: every team, owner class, priority, exposure " +
			"and signal that actually appears, with counts. Call this before filtering or before " +
			"reporting on a team whose exact name you are unsure of, rather than guessing a value " +
			"and reading an empty result as an empty queue.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, _ noArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		return result(facets(a))
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "explain_cve",
		Description: "One CVE across the whole estate: which services and teams carry it, whether " +
			"any of them is internet-facing, its exploitability, whether a fix is published, and how " +
			"many affected deployments a base rebuild would actually clear it on.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, args cveArgs) (*sdk.CallToolResult, any, error) {
		a := src()
		if !a.ready() {
			return textResult(errNoAssessment), nil, nil
		}
		r, ok := cveReport(a, args.ID)
		if !ok {
			return textResult(fmt.Sprintf(
				"%s appears on no scanned image in this assessment. Note that per-CVE detail exists "+
					"only for scanned deployments, so this is not proof the estate is unaffected.",
				args.ID)), nil, nil
		}
		return result(r)
	})
}

// result returns v as both structured content and indented JSON text. The text
// copy is there because clients differ in which they show, and an answer the user
// cannot see is not an answer.
func result(v any) (*sdk.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return textResult(string(b)), v, nil
}

func textResult(s string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: s}}}
}
