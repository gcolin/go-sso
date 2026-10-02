package httpapi

import "testing"

func TestResolveIdPLogo(t *testing.T) {
	cases := []struct {
		id, logo, want string
	}{
		{"google", "", "bi-google"},
		{"microsoft", "", "bi-microsoft"},
		{"facebook", "", "bi-facebook"},
		{"yahoo", "", "bi-globe"},
		{"custom", "", ""},
		{"x", "bi-github", "bi-github"},
		{"x", "google", "bi-google"},
		{"x", "my-custom", "my-custom"},
	}
	for _, c := range cases {
		if got := resolveIdPLogo(c.id, c.logo); got != c.want {
			t.Fatalf("id=%q logo=%q: got %q want %q", c.id, c.logo, got, c.want)
		}
	}
}
