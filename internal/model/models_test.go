package model

import "testing"

func TestHumanizeClientID(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"ticket-test":    "Ticket Test",
		"chess_progress": "Chess Progress",
		"TestApp":        "Testapp",
	}
	for in, want := range cases {
		if got := HumanizeClientID(in); got != want {
			t.Fatalf("HumanizeClientID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOAuthClientDisplayLabel(t *testing.T) {
	c := &OAuthClient{ClientID: "ticket-test", DisplayName: " Tournois test "}
	if got := c.DisplayLabel(); got != "Tournois test" {
		t.Fatalf("DisplayLabel=%q", got)
	}
	c.DisplayName = ""
	if got := c.DisplayLabel(); got != "Ticket Test" {
		t.Fatalf("fallback DisplayLabel=%q", got)
	}
}
