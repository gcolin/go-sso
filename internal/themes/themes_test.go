package themes

import (
	"testing"
	"testing/fstest"
)

func TestEffective(t *testing.T) {
	if got := Effective("tregor", "base"); got != "tregor" {
		t.Fatalf("got %q", got)
	}
	if got := Effective("", "tregor"); got != "tregor" {
		t.Fatalf("got %q", got)
	}
	if got := Effective("", ""); got != BaseTheme {
		t.Fatalf("got %q", got)
	}
}

func TestResolveTemplateOverrideAndParent(t *testing.T) {
	mem := fstest.MapFS{
		"mustache/login.mustache":                    &fstest.MapFile{Data: []byte("BASE_LOGIN")},
		"mustache/head.mustache":                     &fstest.MapFile{Data: []byte("BASE_HEAD")},
		"themes/child/theme.json":                    &fstest.MapFile{Data: []byte(`{"parent":"base","displayName":"Child"}`)},
		"themes/child/mustache/login.mustache":       &fstest.MapFile{Data: []byte("CHILD_LOGIN")},
		"themes/child/static/css/theme.css":          &fstest.MapFile{Data: []byte("/* child */")},
		"themes/grandchild/theme.json":               &fstest.MapFile{Data: []byte(`{"parent":"child"}`)},
		"themes/grandchild/mustache/head.mustache":   &fstest.MapFile{Data: []byte("GC_HEAD")},
	}
	reg := New(mem, "")
	got, err := reg.ResolveTemplate("child", "login")
	if err != nil || got != "CHILD_LOGIN" {
		t.Fatalf("child login: %q %v", got, err)
	}
	got, err = reg.ResolveTemplate("child", "head")
	if err != nil || got != "BASE_HEAD" {
		t.Fatalf("child head fallback: %q %v", got, err)
	}
	got, err = reg.ResolveTemplate("grandchild", "login")
	if err != nil || got != "CHILD_LOGIN" {
		t.Fatalf("grandchild inherits child login: %q %v", got, err)
	}
	got, err = reg.ResolveTemplate("grandchild", "head")
	if err != nil || got != "GC_HEAD" {
		t.Fatalf("grandchild head: %q %v", got, err)
	}
	if !reg.HasThemeCSS("child") {
		t.Fatal("expected theme css")
	}
	if reg.HasThemeCSS(BaseTheme) {
		t.Fatal("base should not have theme css")
	}
}

func TestResolveChainCycle(t *testing.T) {
	mem := fstest.MapFS{
		"themes/a/theme.json": &fstest.MapFile{Data: []byte(`{"parent":"b"}`)},
		"themes/b/theme.json": &fstest.MapFile{Data: []byte(`{"parent":"a"}`)},
	}
	reg := New(mem, "")
	if _, err := reg.ResolveChain("a"); err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestListIncludesBaseAndThemes(t *testing.T) {
	mem := fstest.MapFS{
		"themes/tregor/theme.json": &fstest.MapFile{Data: []byte(`{"parent":"base","displayName":"Trégor"}`)},
	}
	reg := New(mem, "")
	list := reg.List()
	if len(list) < 2 {
		t.Fatalf("list=%v", list)
	}
	if list[0].ID != BaseTheme {
		t.Fatalf("base should be first: %v", list)
	}
	var found bool
	for _, i := range list {
		if i.ID == "tregor" && i.DisplayName == "Trégor" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tregor missing: %v", list)
	}
}

func TestOpenStatic(t *testing.T) {
	mem := fstest.MapFS{
		"themes/tregor/theme.json":            &fstest.MapFile{Data: []byte(`{"parent":"base"}`)},
		"themes/tregor/static/css/theme.css":  &fstest.MapFile{Data: []byte("body{}")},
	}
	reg := New(mem, "")
	f, err := reg.OpenStatic("tregor", "css/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := reg.OpenStatic("tregor", "../theme.json"); err == nil {
		t.Fatal("expected path traversal reject")
	}
	if _, err := reg.OpenStatic("tregor", "css/missing.css"); err == nil {
		t.Fatal("expected missing")
	}
}
