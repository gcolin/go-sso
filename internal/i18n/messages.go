package i18n

import (
	"bufio"
	"fmt"
	"io/fs"
	"strings"
	"sync"
)

// Messages loads Java-style .properties bundles and exposes a nested tree for Mustache.
type Messages struct {
	mu      sync.RWMutex
	bundles map[string]map[string]string // locale -> key -> value
}

func New() *Messages {
	return &Messages{bundles: map[string]map[string]string{}}
}

// LoadFS loads messages_<lang>.properties files from dir (e.g. "i18n").
func (m *Messages) LoadFS(fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "messages_") || !strings.HasSuffix(name, ".properties") {
			continue
		}
		lang := strings.TrimSuffix(strings.TrimPrefix(name, "messages_"), ".properties")
		data, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return err
		}
		m.bundles[lang] = parseProperties(string(data))
	}
	return nil
}

func (m *Messages) Get(lang, key string, args ...any) string {
	pattern := m.resolve(lang, key)
	if len(args) == 0 {
		return unescapeQuotes(pattern)
	}
	return formatMessage(pattern, args...)
}

func (m *Messages) Resolve(lang, key, fallback string) string {
	if v := m.resolve(lang, key); v != key {
		return unescapeQuotes(v)
	}
	if fallback != "" {
		return fallback
	}
	return key
}

func (m *Messages) Tree(lang string) map[string]any {
	keys := map[string]struct{}{}
	for k := range m.bundle("en") {
		keys[k] = struct{}{}
	}
	for k := range m.bundle(lang) {
		keys[k] = struct{}{}
	}
	root := map[string]any{}
	for key := range keys {
		cursor := root
		parts := strings.Split(key, ".")
		for i, part := range parts {
			if i == len(parts)-1 {
				cursor[part] = m.Get(lang, key)
				continue
			}
			next, ok := cursor[part].(map[string]any)
			if !ok {
				next = map[string]any{}
				cursor[part] = next
			}
			cursor = next
		}
	}
	return root
}

func (m *Messages) resolve(lang, key string) string {
	if b := m.bundle(lang); b != nil {
		if v, ok := b[key]; ok {
			return v
		}
	}
	if lang != "en" {
		if b := m.bundle("en"); b != nil {
			if v, ok := b[key]; ok {
				return v
			}
		}
	}
	return key
}

func (m *Messages) bundle(lang string) map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundles[lang]
}

func parseProperties(data string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.IndexAny(line, "=:")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		out[key] = unescapeProperties(val)
	}
	return out
}

func unescapeProperties(s string) string {
	// Keep '' as MessageFormat quote; convert \uXXXX if present is optional.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
			case 't':
				b.WriteByte('\t')
				i++
			case '\\':
				b.WriteByte('\\')
				i++
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unescapeQuotes(s string) string {
	return strings.ReplaceAll(s, "''", "'")
}

func formatMessage(pattern string, args ...any) string {
	out := unescapeQuotes(pattern)
	for i, arg := range args {
		token := fmt.Sprintf("{%d}", i)
		out = strings.ReplaceAll(out, token, fmt.Sprint(arg))
	}
	return out
}
