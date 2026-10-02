package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
)

const (
	prefixSHA256      = "pbkdf2-sha256"
	prefixSHA512      = "pbkdf2-sha512"
	defaultIterations = 210_000
	saltLengthBytes   = 16
	sha256KeyLength   = 32
)

// HashPassword creates a Datanode-native pbkdf2-sha256 hash (UTF-8 password bytes).
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLengthBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2.Key([]byte(password), salt, defaultIterations, sha256KeyLength, sha256.New)
	return formatHash(prefixSHA256, defaultIterations, salt, dk), nil
}

// VerifyPassword checks a password against an encoded PBKDF2 hash.
// It accepts both Datanode-native hashes (UTF-8 password bytes) and
// Keycloak/Java JCE hashes (UTF-16BE password bytes via PBEKeySpec).
func VerifyPassword(password, encodedHash string) bool {
	if password == "" || !IsValidPasswordFormat(encodedHash) {
		return false
	}
	parts := strings.Split(encodedHash, "$")
	prefix := strings.ToLower(parts[0])
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false
	}
	h := hashFuncFor(prefix)
	if h == nil {
		return false
	}
	if matchPBKDF2([]byte(password), salt, iterations, expected, h) {
		return true
	}
	// Keycloak / Java SunJCE PBKDF2 encodes the password as UTF-16BE code units.
	return matchPBKDF2(passwordUTF16BE(password), salt, iterations, expected, h)
}

func matchPBKDF2(passwordBytes, salt []byte, iterations int, expected []byte, h func() hash.Hash) bool {
	actual := pbkdf2.Key(passwordBytes, salt, iterations, len(expected), h)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// passwordUTF16BE mirrors Java PBEKeySpec / Keycloak PBKDF2 password encoding.
func passwordUTF16BE(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		out[i*2] = byte(u >> 8)
		out[i*2+1] = byte(u)
	}
	return out
}

// IsValidPasswordFormat reports whether the encoded hash looks like pbkdf2-sha256/512.
func IsValidPasswordFormat(encodedHash string) bool {
	if strings.TrimSpace(encodedHash) == "" {
		return false
	}
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return false
	}
	prefix := strings.ToLower(parts[0])
	if prefix != prefixSHA256 && prefix != prefixSHA512 {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return false
	}
	hashBytes, err := base64.StdEncoding.DecodeString(parts[3])
	return err == nil && len(hashBytes) > 0
}

func formatHash(prefix string, iterations int, salt, hashBytes []byte) string {
	return fmt.Sprintf("%s$%d$%s$%s",
		prefix,
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hashBytes),
	)
}

func hashFuncFor(prefix string) func() hash.Hash {
	switch prefix {
	case prefixSHA512:
		return sha512.New
	case prefixSHA256:
		return sha256.New
	default:
		return nil
	}
}

// IsValidFormat is an alias for IsValidPasswordFormat.
func IsValidFormat(encodedHash string) bool {
	return IsValidPasswordFormat(encodedHash)
}
