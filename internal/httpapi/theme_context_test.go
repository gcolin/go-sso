package httpapi

import "testing"

func TestClientIDFromReturnURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/oauth/authorize?client_id=chessprogress&response_type=code", "chessprogress"},
		{"/oauth/authorize?response_type=code", ""},
		{"https://sso.example/sso/oauth/authorize?client_id=abc", "abc"},
	}
	for _, c := range cases {
		if got := clientIDFromReturnURL(c.in); got != c.want {
			t.Fatalf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}
