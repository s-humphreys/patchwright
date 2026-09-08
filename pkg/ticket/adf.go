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
// lists, tables, bold, and bare URLs. It is deliberately not a Markdown
// implementation.

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
		lines := foldWrapped(nonEmptyLines(block))
		if len(lines) == 0 {
			continue
		}
		switch {
		case allBullets(lines):
			out = append(out, bulletList(lines))
		case len(lines) == 1 && isHeading(lines[0]):
			out = append(out, heading(lines[0]))
		default:
			// A table or bullet list can follow a lead-in line in the same block
			// ("Fixable critical CVEs:" then the items), so split rather than
			// flattening the whole thing into one paragraph.
			if i := firstTableRow(lines); i >= 0 && isTable(lines[i:]) {
				if i > 0 {
					out = append(out, blockFor(lines[:i]))
				}
				out = append(out, table(lines[i:]))
				continue
			}
			if i := firstBullet(lines); i > 0 {
				out = append(out, blockFor(lines[:i]), bulletList(lines[i:]))
				continue
			}
			out = append(out, blockFor(lines))
		}
	}
	return out
}

// foldWrapped joins a line that continues the bullet above it onto that bullet.
//
// A template author wrapping a long bullet across two lines is writing one
// bullet, but the block then contains a non-bullet line, which used to demote
// the entire block to a paragraph and render every "*" literally. Folding first
// means the wrapping is invisible, which is what the author intended, and a
// genuinely separate paragraph is still expressed the normal way: a blank line.
func foldWrapped(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(out) > 0 && isBullet(out[len(out)-1]) && !isBullet(l) && !isHeading(l) && !isTableRow(l) {
			out[len(out)-1] += " " + l
			continue
		}
		out = append(out, l)
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

// inline parses `code`, **bold** and bare URLs into ADF text nodes with marks.
// Anything else is passed through as plain text, so an unrecognised construct
// shows as the author typed it rather than being mangled.
//
// Code is resolved first and its contents are left alone: an image reference or a
// command is exactly the kind of thing that contains characters the other rules
// would otherwise treat as markup, and a URL inside code should stay code rather
// than becoming a link.
func inline(s string) []any {
	var out []any
	for _, seg := range splitCode(s) {
		if seg.code {
			out = append(out, textNode(seg.text, []any{map[string]any{"type": "code"}}))
			continue
		}
		for _, b := range splitBold(seg.text) {
			if b.bold {
				out = append(out, linkify(b.text, []any{map[string]any{"type": "strong"}})...)
				continue
			}
			out = append(out, linkify(b.text, nil)...)
		}
	}
	if len(out) == 0 {
		out = []any{map[string]any{"type": "text", "text": s}}
	}
	return out
}

// splitCode separates `code` spans from the surrounding text.
//
// An unmatched backtick is left as literal text rather than swallowing the rest of
// the line, on the same principle as the bold parser: a stray character in a
// template should look wrong, not silently reformat everything after it.
func splitCode(s string) []segment {
	var out []segment
	for {
		start := strings.Index(s, "`")
		if start < 0 {
			break
		}
		end := strings.Index(s[start+1:], "`")
		if end < 0 {
			break
		}
		if start > 0 {
			out = append(out, segment{text: s[:start]})
		}
		out = append(out, segment{text: s[start+1 : start+1+end], code: true})
		s = s[start+1+end+1:]
	}
	if s != "" {
		out = append(out, segment{text: s})
	}
	return out
}

type segment struct {
	text string
	bold bool
	code bool
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

// Tables.
//
// Markdown pipe tables, because a ticket that lists where a service runs reads
// better as rows than as a sentence per deployment:
//
//	| Tag | Namespace |
//	| --- | --------- |
//	| v1.6.5 | sealed-secrets-tools |
//
// The delimiter row is required, as it is in Markdown: without it a line
// beginning with "|" is more likely to be prose than a table, and guessing wrong
// turns a paragraph into a one-column table.

func isTableRow(line string) bool {
	return strings.HasPrefix(line, "|") && strings.HasSuffix(line, "|") && len(line) > 1
}

func firstTableRow(lines []string) int {
	for i, l := range lines {
		if isTableRow(l) {
			return i
		}
	}
	return -1
}

// isTable reports whether lines start a table: a header row, then a delimiter
// row. Anything after them that is not a row ends it.
func isTable(lines []string) bool {
	return len(lines) >= 2 && isTableRow(lines[0]) && isDelimiterRow(lines[1])
}

func isDelimiterRow(line string) bool {
	if !isTableRow(line) {
		return false
	}
	cells := tableCells(line)
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		c = strings.TrimSpace(c)
		c = strings.TrimPrefix(c, ":")
		c = strings.TrimSuffix(c, ":")
		// One dash is enough. Markdown conventionally wants three, but a column
		// whose separator is a character short is a typo, and failing it turns the
		// whole table into literal pipes in Jira — a bad trade for strictness.
		if c == "" || strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

// tableCells splits one row on unescaped pipes, dropping the leading and
// trailing empties the delimiters create.
func tableCells(line string) []string {
	parts := strings.Split(strings.Trim(line, "|"), "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// table builds an ADF table from a header row, a delimiter row and the body rows
// that follow. Rows are padded or truncated to the header's width: Jira renders a
// ragged table badly, and a missing cell is likelier a template's empty value
// than an intent to merge.
func table(lines []string) any {
	header := tableCells(lines[0])
	rows := []any{tableRow(header, "tableHeader", len(header))}
	for _, l := range lines[2:] {
		if !isTableRow(l) {
			break
		}
		rows = append(rows, tableRow(tableCells(l), "tableCell", len(header)))
	}
	return map[string]any{
		"type":    "table",
		"attrs":   map[string]any{"isNumberColumnEnabled": false, "layout": "default"},
		"content": rows,
	}
}

func tableRow(cells []string, cellType string, width int) any {
	content := make([]any, 0, width)
	for i := 0; i < width; i++ {
		var text string
		if i < len(cells) {
			text = cells[i]
		}
		para := map[string]any{"type": "paragraph"}
		if text != "" {
			para["content"] = inline(text)
		}
		content = append(content, map[string]any{
			"type":    cellType,
			"attrs":   map[string]any{"colspan": 1, "rowspan": 1},
			"content": []any{para},
		})
	}
	return map[string]any{"type": "tableRow", "content": content}
}
