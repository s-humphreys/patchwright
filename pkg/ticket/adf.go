package ticket

import "strings"

// Atlassian Document Format conversion.
//
// Jira's v3 API takes ADF, not text: anything sent as a plain paragraph renders
// with its markup literal, so "**Heading**" appears with the asterisks showing
// and "* item" lines collapse into one run-on paragraph. Templates are written in
// Markdown-ish notation because that is what a person editing a ticket template
// expects to type, so the notation has to be converted rather than passed through.
//
// This handles the subset a ticket template actually uses: headings, bullet
// lists, bold, and bare URLs. It is deliberately not a Markdown implementation.

// ADFDocument converts template output to an ADF document.
func ADFDocument(text string) map[string]any {
	content := adfBlocks(text)
	if len(content) == 0 {
		content = []any{map[string]any{"type": "paragraph"}}
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

func adfBlocks(text string) []any {
	var out []any
	for _, block := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		lines := nonEmptyLines(block)
		if len(lines) == 0 {
			continue
		}
		switch {
		case allBullets(lines):
			out = append(out, bulletList(lines))
		case len(lines) == 1 && isHeading(lines[0]):
			out = append(out, heading(lines[0]))
		default:
			// A bullet list can follow a lead-in line in the same block ("Fixable
			// critical CVEs:" then the items), so split rather than flattening the
			// whole thing into one paragraph.
			if i := firstBullet(lines); i > 0 {
				out = append(out, blockFor(lines[:i]), bulletList(lines[i:]))
				continue
			}
			out = append(out, blockFor(lines))
		}
	}
	return out
}

func blockFor(lines []string) any {
	if len(lines) == 1 && isHeading(lines[0]) {
		return heading(lines[0])
	}
	return paragraph(lines)
}

func nonEmptyLines(block string) []string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func isBullet(line string) bool {
	return strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ")
}

func allBullets(lines []string) bool {
	for _, l := range lines {
		if !isBullet(l) {
			return false
		}
	}
	return true
}

func firstBullet(lines []string) int {
	for i, l := range lines {
		if isBullet(l) {
			return i
		}
	}
	return -1
}

func isHeading(line string) bool {
	// Markdown "## Heading", or a whole line wrapped in bold, which is how the
	// bundled template writes its section headings.
	if strings.HasPrefix(line, "#") {
		return strings.Contains(line, " ")
	}
	return strings.HasPrefix(line, "**") && strings.HasSuffix(line, "**") && len(line) > 4
}

func heading(line string) any {
	level := 3
	text := line
	if strings.HasPrefix(line, "#") {
		hashes := len(line) - len(strings.TrimLeft(line, "#"))
		level = min(max(hashes, 1), 6)
		text = strings.TrimSpace(line[hashes:])
	} else {
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "**"), "**"))
	}
	return map[string]any{
		"type":    "heading",
		"attrs":   map[string]any{"level": level},
		"content": inline(text),
	}
}

func bulletList(lines []string) any {
	items := make([]any, 0, len(lines))
	for _, l := range lines {
		items = append(items, map[string]any{
			"type": "listItem",
			"content": []any{map[string]any{
				"type":    "paragraph",
				"content": inline(strings.TrimSpace(l[2:])),
			}},
		})
	}
	return map[string]any{"type": "bulletList", "content": items}
}

// paragraph joins lines with hard breaks, so a template's line structure
// survives instead of becoming one run-on line.
func paragraph(lines []string) any {
	var content []any
	for i, l := range lines {
		if i > 0 {
			content = append(content, map[string]any{"type": "hardBreak"})
		}
		content = append(content, inline(l)...)
	}
	return map[string]any{"type": "paragraph", "content": content}
}

// inline parses **bold** and bare URLs into ADF text nodes with marks. Anything
// else is passed through as plain text, so an unrecognised construct shows as
// the author typed it rather than being mangled.
func inline(s string) []any {
	var out []any
	for _, seg := range splitBold(s) {
		if seg.bold {
			out = append(out, linkify(seg.text, []any{map[string]any{"type": "strong"}})...)
			continue
		}
		out = append(out, linkify(seg.text, nil)...)
	}
	if len(out) == 0 {
		out = []any{map[string]any{"type": "text", "text": s}}
	}
	return out
}

type segment struct {
	text string
	bold bool
}

func splitBold(s string) []segment {
	var out []segment
	for {
		start := strings.Index(s, "**")
		if start < 0 {
			break
		}
		end := strings.Index(s[start+2:], "**")
		if end < 0 {
			break
		}
		if start > 0 {
			out = append(out, segment{text: s[:start]})
		}
		out = append(out, segment{text: s[start+2 : start+2+end], bold: true})
		s = s[start+2+end+2:]
	}
	if s != "" {
		out = append(out, segment{text: s})
	}
	return out
}

// linkify turns bare http(s) URLs into link marks, so a change target in a
// ticket is clickable rather than something to copy out by hand.
func linkify(s string, marks []any) []any {
	var out []any
	for len(s) > 0 {
		i := strings.Index(s, "http")
		if i < 0 || !(strings.HasPrefix(s[i:], "http://") || strings.HasPrefix(s[i:], "https://")) {
			// No URL start here; emit what is left (or skip past a false "http").
			if i < 0 {
				out = append(out, textNode(s, marks))
				break
			}
			out = append(out, textNode(s[:i+4], marks))
			s = s[i+4:]
			continue
		}
		if i > 0 {
			out = append(out, textNode(s[:i], marks))
		}
		rest := s[i:]
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		url := strings.TrimRight(rest[:end], ".,;:)")
		linkMarks := append(append([]any{}, marks...), map[string]any{
			"type":  "link",
			"attrs": map[string]any{"href": url},
		})
		out = append(out, textNode(url, linkMarks))
		s = rest[len(url):]
	}
	return out
}

func textNode(text string, marks []any) any {
	n := map[string]any{"type": "text", "text": text}
	if len(marks) > 0 {
		n["marks"] = marks
	}
	return n
}
