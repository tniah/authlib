package rfc6749

import (
	"net/http"
	"time"
)

type AuthorizationRequest struct {
	ClientID            string
	ResponseType        ResponseType
	RedirectURI         string
	Scope               string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	Client              OAuthClient
	Request             *http.Request
}

type AuthorizationCodeRequest struct {
	ClientID            string
	Code                string
	UserID              string
	RedirectURI         string
	ResponseType        ResponseType
	Scope               string
	Nonce               string
	AuthTime            time.Time
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	User                User
	Client              OAuthClient
	Request             *http.Request
}

type TokenRequest struct {
	AccessToken           string
	RefreshToken          string
	ClientID              string
	TokenType             string
	Scope                 string
	IssuedAt              time.Time
	ExpiresIn             time.Duration
	AccessTokenRevokedAt  time.Time
	RefreshTokenRevokedAt time.Time
	UserID                string
	User                  User
	Client                OAuthClient
	Request               *http.Request
}
