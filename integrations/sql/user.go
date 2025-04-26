package sql

type User struct {
	UserID string `json:"userid"`
}

func (u *User) GetUserID() string {
	return u.UserID
}
