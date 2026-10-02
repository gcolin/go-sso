package themes

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const BaseTheme = "base"

// Manifest is themes/{name}/theme.json.
type Manifest struct {
	Parent      string `json:"parent"`
	DisplayName string `json:"displayName"`
}

// Info describes a discoverable theme for admin UI.
type Info struct {
	ID          string
	DisplayName string
	Parent      string
}

// Registry resolves Mustache templates and static assets with Keycloak-like parent inheritance.
// Base templates come from embedFS (mustache/). Named themes are loaded from diskDir only
// (next to sso-server.json); they are not embedded in the binary.
type Registry struct {
	embedFS fs.FS // base mustache/static only
	diskDir string
	cache   sync.Map // key: theme+"\x00"+name -> string
}

func New(embedFS fs.FS, themesDir string) *Registry {
	return &Registry{
		embedFS: embedFS,
		diskDir: strings.TrimSpace(themesDir),
	}
}

// DiskDir returns the configured on-disk themes root.
func (r *Registry) DiskDir() string {
	if r == nil {
		return ""
	}
	return r.diskDir
}

// Effective returns client theme, else server default, else base.
func Effective(clientTheme, defaultTheme string) string {
	if t := strings.TrimSpace(clientTheme); t != "" {
		return t
	}
	if t := strings.TrimSpace(defaultTheme); t != "" {
		return t
	}
	return BaseTheme
}

func (r *Registry) Exists(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || id == BaseTheme {
		return true
	}
	if r.hasDiskTheme(id) {
		return true
	}
	return r.hasEmbedTheme(id)
}

func (r *Registry) List() []Info {
	seen := map[string]Info{
		BaseTheme: {ID: BaseTheme, DisplayName: "Base (Pico)", Parent: ""},
	}
	for _, id := range r.listEmbedThemeIDs() {
		info := r.infoFor(id)
		seen[id] = info
	}
	for _, id := range r.listDiskThemeIDs() {
		info := r.infoFor(id)
		seen[id] = info
	}
	out := make([]Info, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == BaseTheme {
			return true
		}
		if out[j].ID == BaseTheme {
			return false
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (r *Registry) infoFor(id string) Info {
	m, err := r.loadManifest(id)
	if err != nil || m == nil {
		return Info{ID: id, DisplayName: id, Parent: BaseTheme}
	}
	name := strings.TrimSpace(m.DisplayName)
	if name == "" {
		name = id
	}
	parent := strings.TrimSpace(m.Parent)
	if parent == "" {
		parent = BaseTheme
	}
	return Info{ID: id, DisplayName: name, Parent: parent}
}

// ResolveChain returns theme → parents → base (no duplicates). Detects cycles.
func (r *Registry) ResolveChain(theme string) ([]string, error) {
	theme = Effective(theme, "")
	var chain []string
	seen := map[string]struct{}{}
	cur := theme
	for {
		if _, ok := seen[cur]; ok {
			return nil, fmt.Errorf("theme parent cycle involving %q", cur)
		}
		seen[cur] = struct{}{}
		chain = append(chain, cur)
		if cur == BaseTheme {
			return chain, nil
		}
		if !r.Exists(cur) {
			return nil, fmt.Errorf("unknown theme %q", cur)
		}
		m, err := r.loadManifest(cur)
		parent := BaseTheme
		if err == nil && m != nil {
			if p := strings.TrimSpace(m.Parent); p != "" {
				parent = p
			}
		}
		cur = parent
	}
}

// ResolveTemplate walks the theme chain then falls back to embedded mustache/.
func (r *Registry) ResolveTemplate(theme, name string) (string, error) {
	name = normalizeTemplate(name)
	cacheKey := theme + "\x00" + name
	if v, ok := r.cache.Load(cacheKey); ok {
		return v.(string), nil
	}
	chain, err := r.ResolveChain(theme)
	if err != nil {
		return "", err
	}
	for _, id := range chain {
		if id == BaseTheme {
			continue
		}
		if data, ok := r.readThemeFile(id, path.Join("mustache", name)); ok {
			r.cache.Store(cacheKey, data)
			return data, nil
		}
	}
	data, err := fs.ReadFile(r.embedFS, path.Join("mustache", name))
	if err != nil {
		return "", fmt.Errorf("missing mustache template: %s", name)
	}
	src := string(data)
	r.cache.Store(cacheKey, src)
	return src, nil
}

// HasThemeCSS reports whether themes/{id}/static/css/theme.css exists.
func (r *Registry) HasThemeCSS(theme string) bool {
	theme = Effective(theme, "")
	if theme == BaseTheme {
		return false
	}
	_, ok := r.readThemeFile(theme, "static/css/theme.css")
	return ok
}

// OpenStatic opens a file under themes/{theme}/static/{rel}. Theme may be any chain member
// that owns the file; callers typically pass the effective theme and rel path as stored.
func (r *Registry) OpenStatic(theme, rel string) (fs.File, error) {
	theme = strings.TrimSpace(theme)
	rel = cleanStaticRel(rel)
	if theme == "" || theme == BaseTheme || rel == "" {
		return nil, fs.ErrNotExist
	}
	if f, err := r.openDisk(path.Join(theme, "static", rel)); err == nil {
		return f, nil
	}
	if r.embedFS == nil {
		return nil, fs.ErrNotExist
	}
	return r.embedFS.Open(path.Join("themes", theme, "static", rel))
}

func cleanStaticRel(rel string) string {
	rel = strings.TrimPrefix(rel, "/")
	rel = path.Clean("/" + rel)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." || rel == "" || strings.HasPrefix(rel, "..") {
		return ""
	}
	return rel
}

func normalizeTemplate(name string) string {
	name = strings.TrimPrefix(name, "/")
	if strings.HasSuffix(name, ".jte") {
		name = strings.TrimSuffix(name, ".jte") + ".mustache"
	} else if !strings.HasSuffix(name, ".mustache") {
		name += ".mustache"
	}
	return name
}

func (r *Registry) loadManifest(id string) (*Manifest, error) {
	data, ok := r.readThemeFile(id, "theme.json")
	if !ok {
		return nil, fs.ErrNotExist
	}
	var m Manifest
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *Registry) readThemeFile(id, rel string) (string, bool) {
	id = strings.TrimSpace(id)
	if id == "" || id == BaseTheme {
		return "", false
	}
	rel = strings.TrimPrefix(rel, "/")
	if r.diskDir != "" {
		p := filepath.Join(r.diskDir, id, filepath.FromSlash(rel))
		if b, err := os.ReadFile(p); err == nil {
			return string(b), true
		}
	}
	if r.embedFS != nil {
		if b, err := fs.ReadFile(r.embedFS, path.Join("themes", id, rel)); err == nil {
			return string(b), true
		}
	}
	return "", false
}

func (r *Registry) openDisk(relUnderThemes string) (fs.File, error) {
	if r.diskDir == "" {
		return nil, fs.ErrNotExist
	}
	p := filepath.Join(r.diskDir, filepath.FromSlash(relUnderThemes))
	return os.Open(p)
}

func (r *Registry) hasEmbedTheme(id string) bool {
	if r.embedFS == nil {
		return false
	}
	_, err := fs.Stat(r.embedFS, path.Join("themes", id))
	return err == nil
}

func (r *Registry) hasDiskTheme(id string) bool {
	if r.diskDir == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(r.diskDir, id))
	return err == nil && st.IsDir()
}

func (r *Registry) listEmbedThemeIDs() []string {
	if r.embedFS == nil {
		return nil
	}
	entries, err := fs.ReadDir(r.embedFS, "themes")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func (r *Registry) listDiskThemeIDs() []string {
	if r.diskDir == "" {
		return nil
	}
	entries, err := os.ReadDir(r.diskDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}
