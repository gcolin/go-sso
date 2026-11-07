package model

import "testing"

func TestAllowedRedirectURIsMergesAndDedupes(t *testing.T) {
	c := OAuthClient{
		RedirectURI:  " http://a.example/cb ",
		RedirectURIs: []string{"http://b.example/cb", "http://a.example/cb", "", "http://c.example/cb"},
	}
	got := c.AllowedRedirectURIs()
	want := []string{"http://a.example/cb", "http://b.example/cb", "http://c.example/cb"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if c.PrimaryRedirectURI() != "http://a.example/cb" {
		t.Fatalf("PrimaryRedirectURI=%q", c.PrimaryRedirectURI())
	}
}

func TestAllowsRedirectURI(t *testing.T) {
	c := OAuthClient{RedirectURIs: []string{"http://app.example/cb"}}
	if !c.AllowsRedirectURI("http://app.example/cb") {
		t.Fatal("expected allow registered uri")
	}
	if c.AllowsRedirectURI("http://evil.example/cb") {
		t.Fatal("expected deny unregistered uri")
	}

	open := OAuthClient{AllowAnyRedirectURI: true}
	if !open.AllowsRedirectURI("http://anywhere.example/x") {
		t.Fatal("expected allow-any")
	}
	if open.AllowsRedirectURI("") {
		t.Fatal("empty uri must still be denied")
	}
}
