package common

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"testing"
)

func TestGenerateJWT(t *testing.T) {
	key := []byte("this-is-my-secret-key")
	token, err := NewJWTToken(key, jwt.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
	}
	jwtToken, err := token.Generate(JWTClaim{"makai": "abc"}, nil)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(jwtToken)
}
