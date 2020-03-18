package auth

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
)

// secureCookie provides a handler to easily set and retrieve encrypted cookies.
type secureCookie struct {
	SC *securecookie.SecureCookie
}

var scSingleton *secureCookie
var scOnce sync.Once

// GetSC returns the singleton secure cookie instance.
// Prepares & generates the keys if need be.
func getSC(configPath string) *secureCookie {
	scOnce.Do(func() {
		kms := getKMS(configPath)
		hashKey := kms.CookiesHash
		blockKey := kms.CookiesBlock

		scSingleton = &secureCookie{
			SC: securecookie.New(hashKey, blockKey),
		}
	})
	return scSingleton
}

// Set creates a secure cookie using the given payload.
func (sc *secureCookie) Set(w http.ResponseWriter, key string, payload cookiePayload, cookieLifetime time.Duration) (err error) {
	// Set the cookie
	if encoded, encErr := sc.SC.Encode(key, payload); encErr == nil {
		cookie := &http.Cookie{
			Name:    key,
			Value:   encoded,
			Path:    "/",
			Secure:  false,
			Expires: time.Now().Add(cookieLifetime),
			MaxAge:  int(cookieLifetime.Seconds()),
		}

		http.SetCookie(w, cookie)
	} else {
		err = encErr
	}
	return
}

// Get retrieves and decodes a secure cookie.
func (sc *secureCookie) Get(r *http.Request, key string) (value cookiePayload, err error) {
	if cookie, err := r.Cookie(key); err == nil {
		err = sc.SC.Decode(key, cookie.Value, &value)
	}
	return
}
