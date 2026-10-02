package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const MethodS256 = "S256"

func IsChallengeRequired(challenge string) bool {
	return strings.TrimSpace(challenge) != ""
}

func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func VerifyS256(verifier, challenge string) bool {
	if strings.TrimSpace(verifier) == "" || strings.TrimSpace(challenge) == "" {
		return false
	}
	return ChallengeS256(verifier) == challenge
}
