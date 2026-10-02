package mustache

import (
	"fmt"
	"html"
	"strings"
	"sync"
)

// Lambda receives the already-rendered section body and returns replacement text
// (HTML-escaped into the output, matching the Java Mustache.Lambda behavior).
type Lambda func(renderedBody string) string

// Partials resolves partial template sources by name (e.g. "head", "head.mustache").
type Partials func(name string) string

type node interface{}

type textNode struct{ text string }
type varNode struct {
	path []string
	raw  bool
}
type sectionNode struct {
	path []string
	body []node
}
type invertedNode struct {
	path []string
	body []node
}
type partialNode struct{ name string }

// Template is a compiled Mustache template.
type Template struct {
	nodes []node
}

var cache sync.Map

// Compile parses and caches a template by source string.
func Compile(source string) *Template {
	if v, ok := cache.Load(source); ok {
		return v.(*Template)
	}
	t := &Template{nodes: parse(source)}
	actual, _ := cache.LoadOrStore(source, t)
	return actual.(*Template)
}

// Render renders with no partials.
func (t *Template) Render(ctx any) string {
	return t.RenderWith(ctx, nil)
}

// RenderWith renders using the given partial resolver.
func (t *Template) RenderWith(ctx any, partials Partials) string {
	var b strings.Builder
	stack := []any{ctx}
	write(t.nodes, stack, partials, &b)
	return b.String()
}

func parse(source string) []node {
	nodes, end := parseNodes(source, 0, len(source), "")
	if end != len(source) {
		panic(fmt.Sprintf("unexpected section end near %d", end))
	}
	return nodes
}

func parseNodes(source string, start, end int, sectionName string) ([]node, int) {
	var nodes []node
	i := start
	for i < end {
		open := strings.Index(source[i:end], "{{")
		if open < 0 {
			if i < end {
				nodes = append(nodes, textNode{source[i:end]})
			}
			return nodes, end
		}
		open += i
		if open > i {
			nodes = append(nodes, textNode{source[i:open]})
		}
		triple := open+2 < end && source[open+2] == '{'
		contentStart := open + 2
		close := "}}"
		if triple {
			contentStart = open + 3
			close = "}}}"
		}
		closeAt := strings.Index(source[contentStart:end], close)
		if closeAt < 0 {
			panic(fmt.Sprintf("unclosed mustache tag at %d", open))
		}
		closeAt += contentStart
		rawTag := strings.TrimSpace(source[contentStart:closeAt])
		next := closeAt + len(close)
		if rawTag == "" {
			i = next
			continue
		}
		sigil := rawTag[0]
		switch sigil {
		case '!':
			i = next
			continue
		case '>':
			nodes = append(nodes, partialNode{strings.TrimSpace(rawTag[1:])})
			i = next
			continue
		case '#', '^':
			name := strings.TrimSpace(rawTag[1:])
			body, bodyEnd := parseNodes(source, next, end, name)
			after := skipCloseTag(source, bodyEnd, end, name)
			path := pathOf(name)
			if sigil == '^' {
				nodes = append(nodes, invertedNode{path, body})
			} else {
				nodes = append(nodes, sectionNode{path, body})
			}
			i = after
			continue
		case '/':
			name := strings.TrimSpace(rawTag[1:])
			if sectionName != "" && sectionName == name {
				return nodes, open
			}
			panic(fmt.Sprintf("unexpected section end: {{/%s}}", name))
		}
		raw := triple || sigil == '&'
		name := rawTag
		if raw && !triple {
			name = strings.TrimSpace(rawTag[1:])
		}
		nodes = append(nodes, varNode{pathOf(name), raw})
		i = next
	}
	if sectionName != "" {
		panic(fmt.Sprintf("unclosed section {{#%s}}", sectionName))
	}
	return nodes, end
}

func skipCloseTag(source string, openAt, end int, name string) int {
	if openAt >= end || !strings.HasPrefix(source[openAt:], "{{") {
		panic(fmt.Sprintf("unclosed section {{#%s}}", name))
	}
	closeAt := strings.Index(source[openAt+2:end], "}}")
	if closeAt < 0 {
		panic(fmt.Sprintf("unclosed section end for %s", name))
	}
	return openAt + 2 + closeAt + 2
}

func pathOf(name string) []string {
	if name == "." {
		return []string{"."}
	}
	return strings.Split(name, ".")
}

func write(nodes []node, stack []any, partials Partials, out *strings.Builder) {
	for _, n := range nodes {
		switch t := n.(type) {
		case textNode:
			out.WriteString(t.text)
		case varNode:
			appendValue(lookup(stack, t.path), t.raw, out)
		case sectionNode:
			writeSection(t.body, stack, partials, out, lookup(stack, t.path))
		case invertedNode:
			if !isTruthy(lookup(stack, t.path)) {
				write(t.body, stack, partials, out)
			}
		case partialNode:
			if partials == nil {
				continue
			}
			src := partials(t.name)
			if src == "" {
				continue
			}
			Compile(src).writeInto(stack, partials, out)
		}
	}
}

func (t *Template) writeInto(stack []any, partials Partials, out *strings.Builder) {
	write(t.nodes, stack, partials, out)
}

func writeSection(body []node, stack []any, partials Partials, out *strings.Builder, value any) {
	if fn, ok := value.(Lambda); ok {
		var rendered strings.Builder
		write(body, stack, partials, &rendered)
		result := fn(rendered.String())
		if result != "" {
			out.WriteString(html.EscapeString(result))
		}
		return
	}
	if !isTruthy(value) {
		return
	}
	switch v := value.(type) {
	case bool:
		write(body, stack, partials, out)
	case []any:
		for _, item := range v {
			stack = append(stack, item)
			write(body, stack, partials, out)
			stack = stack[:len(stack)-1]
		}
	case []string:
		for _, item := range v {
			stack = append(stack, item)
			write(body, stack, partials, out)
			stack = stack[:len(stack)-1]
		}
	case []map[string]any:
		for _, item := range v {
			stack = append(stack, item)
			write(body, stack, partials, out)
			stack = stack[:len(stack)-1]
		}
	default:
		stack = append(stack, value)
		write(body, stack, partials, out)
		stack = stack[:len(stack)-1]
	}
}

func appendValue(value any, raw bool, out *strings.Builder) {
	if value == nil || value == missing {
		return
	}
	text := fmt.Sprint(value)
	if raw {
		out.WriteString(text)
	} else {
		out.WriteString(html.EscapeString(text))
	}
}

var missing = &struct{}{}

func isTruthy(value any) bool {
	if value == nil || value == missing {
		return false
	}
	switch v := value.(type) {
	case Lambda:
		return true
	case bool:
		return v
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case []string:
		return len(v) > 0
	case []map[string]any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

func lookup(stack []any, path []string) any {
	if len(path) == 0 {
		return nil
	}
	if len(path) == 1 && path[0] == "." {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	for s := len(stack) - 1; s >= 0; s-- {
		first := resolveKey(stack[s], path[0])
		if first == missing {
			continue
		}
		current := first
		for p := 1; p < len(path); p++ {
			if current == nil {
				return nil
			}
			current = resolveKey(current, path[p])
			if current == missing {
				return nil
			}
		}
		return current
	}
	return nil
}

func resolveKey(context any, key string) any {
	if context == nil {
		return missing
	}
	switch c := context.(type) {
	case map[string]any:
		v, ok := c[key]
		if !ok {
			return missing
		}
		return v
	default:
		return missing
	}
}
