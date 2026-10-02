package oauth

import "testing"

func TestPkceS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := ChallengeS256(verifier)
	// RFC 7636 Appendix B
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challenge != want {
		t.Fatalf("challenge=%s want=%s", challenge, want)
	}
	if !VerifyS256(verifier, challenge) {
		t.Fatal("verify failed")
	}
	if VerifyS256("wrong", challenge) {
		t.Fatal("verify succeeded for wrong verifier")
	}
	if !IsChallengeRequired(challenge) {
		t.Fatal("challenge should be required")
	}
	if IsChallengeRequired("") {
		t.Fatal("empty challenge should not be required")
	}
}
