package rfc7636

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

// CodeVerifierPattern is the ABNF pattern for a valid code_verifier per RFC 7636 §4.1.
const CodeVerifierPattern = "^[a-zA-Z0-9\\-._~]{43,128}$"

var codeVerifierRe = regexp.MustCompile(CodeVerifierPattern)

// CreateS256CodeChallenge computes the S256 code_challenge for the given
// code_verifier: BASE64URL(SHA256(ASCII(verifier))).
func CreateS256CodeChallenge(verifier string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ValidateCodeVerifierPattern reports whether verifier matches the allowed
// character set and length (43–128 characters) defined in RFC 7636 §4.1.
func ValidateCodeVerifierPattern(verifier string) bool {
	return codeVerifierRe.MatchString(verifier)
}
