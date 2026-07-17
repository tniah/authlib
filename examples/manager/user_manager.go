package manager

import (
	"context"
	"net/http"
	"sync"
	"time"

	authlibmodels "github.com/tniah/authlib/models"
	authlibrequests "github.com/tniah/authlib/requests"
)

// User is an in-memory user model with standard OIDC profile claims
// (OpenID Connect Core 1.0 §5.1).
type User struct {
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	Password      string    `json:"-"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
	MiddleName    string    `json:"middle_name"`
	Nickname      string    `json:"nickname"`
	Picture       string    `json:"picture"`
	Website       string    `json:"website"`
	PhoneNumber   string    `json:"phone_number"`
	Locale        string    `json:"locale"`
	ZoneInfo      string    `json:"zoneinfo"`
	UpdatedAt     time.Time `json:"updated_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// GetUserID returns the unique identifier of the user.
func (u *User) GetUserID() string {
	return u.UserID
}

// UserManager handles user lookup and authentication for OAuth2 flows.
type UserManager struct {
	lock       sync.Mutex
	byID       map[string]*User
	byUsername map[string]*User
}

// NewUserManager creates a new UserManager with pre-seeded test users.
func NewUserManager() *UserManager {
	now := time.Now().UTC().Round(time.Second)
	users := []*User{
		{
			UserID:        "usr_alice001",
			Username:      "alice",
			Password:      "secret",
			Email:         "alice@example.com",
			EmailVerified: true,
			Name:          "Alice Smith",
			GivenName:     "Alice",
			FamilyName:    "Smith",
			MiddleName:    "Marie",
			Nickname:      "ally",
			Picture:       "https://i.pravatar.cc/150?u=alice",
			Website:       "https://alice.example.com",
			PhoneNumber:   "+1-202-555-0101",
			Locale:        "en-US",
			ZoneInfo:      "America/New_York",
			CreatedAt:     now,
			UpdatedAt:     now,
		},
		{
			UserID:        "usr_bob002",
			Username:      "bob",
			Password:      "password",
			Email:         "bob@example.com",
			EmailVerified: false,
			Name:          "Bob Nguyen",
			GivenName:     "Bob",
			FamilyName:    "Nguyen",
			Nickname:      "bobby",
			Picture:       "https://i.pravatar.cc/150?u=bob",
			Website:       "https://bob.example.com",
			PhoneNumber:   "+84-90-555-0202",
			Locale:        "vi-VN",
			ZoneInfo:      "Asia/Ho_Chi_Minh",
			CreatedAt:     now,
			UpdatedAt:     now,
		},
	}

	m := &UserManager{
		byID:       make(map[string]*User, len(users)),
		byUsername: make(map[string]*User, len(users)),
	}
	for _, u := range users {
		m.byID[u.UserID] = u
		m.byUsername[u.Username] = u
	}
	return m
}

// QueryUserByCode retrieves the user associated with the given authorization code.
// Returns (nil, nil) when no user is found for the code's user ID.
func (m *UserManager) QueryUserByCode(ctx context.Context, code authlibmodels.AuthorizationCode, r *authlibrequests.TokenRequest) (authlibmodels.User, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	u, ok := m.byID[code.GetUserID()]
	if !ok {
		return nil, nil
	}

	return u, nil
}

// Authenticate verifies the user's credentials and returns the authenticated user.
// Returns (nil, nil) when the credentials are invalid.
func (m *UserManager) Authenticate(username, password string, client authlibmodels.Client, r *http.Request) (authlibmodels.User, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	u, ok := m.byUsername[username]
	if !ok || u.Password != password {
		return nil, nil
	}

	return u, nil
}
