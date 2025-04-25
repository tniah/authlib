package rfc7636

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

const CodeVerifierPattern = "^[a-zA-Z0-9\\-._~]{43,128}$"

func CreateS256CodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func ValidateCodeVerifierPattern(verifier string) bool {
	rg, _ := regexp.Compile(CodeVerifierPattern)
	return rg.Match([]byte(verifier))
}
