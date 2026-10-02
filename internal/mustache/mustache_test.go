package mustache

import "testing"

func TestSectionIteratesStringSlice(t *testing.T) {
	tpl := Compile("{{#items}}<li>{{.}}</li>{{/items}}")
	got := tpl.Render(map[string]any{
		"items": []string{"alpha", "beta"},
	})
	want := "<li>alpha</li><li>beta</li>"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEmptyStringSliceIsFalsy(t *testing.T) {
	tpl := Compile("{{#items}}x{{/items}}{{^items}}empty{{/items}}")
	got := tpl.Render(map[string]any{"items": []string{}})
	if got != "empty" {
		t.Fatalf("got %q", got)
	}
}
