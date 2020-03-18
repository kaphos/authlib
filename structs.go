package auth

import "time"

// cookiePayload is the structure of the cookie that is used
// to authenticate users after they have logged in.
type cookiePayload struct {
	Key   string
	Token string
}

// LoginPayload contains the login details that is being passed in to be checked & stored.
type LoginPayload struct {
	ID               string // Unique identifier of the user
	Username         string
	ProvidedPassword string
	PasswordHash     string
	RmbMe            bool
}

type storeValue struct {
	HashedToken string
	UserID      string
	Expires     time.Time
	MaxExpiry   time.Time
}
