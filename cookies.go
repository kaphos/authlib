package authlib

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
)

// secureCookie provides a handler to easily set and retrieve encrypted cookies.
type secureCookie struct {
	SC     *securecookie.SecureCookie
	config Config
}

var scSingleton *secureCookie
var scOnce sync.Once

// GetSC returns the singleton secure cookie instance.
// Prepares & generates the keys if need be.
func getSC(config Config) *secureCookie {
	scOnce.Do(func() {
		kms := getKMS(config.KMSPath)
		hashKey := kms.CookiesHash
		blockKey := kms.CookiesBlock

		scSingleton = &secureCookie{
			SC:     securecookie.New(hashKey, blockKey),
			config: config,
		}
	})
	return scSingleton
}

// Set creates a secure cookie using the given payload.
func (sc *secureCookie) Set(w http.ResponseWriter, key string, payload cookieValue, cookieLifetime time.Duration) (err error) {
	// Set the cookie
	if cookieLifetime > 0 {
		payload.Expires = time.Now().Add(cookieLifetime)
	}
	if encoded, encErr := sc.SC.Encode(key, payload); encErr == nil {
		path := "/"
		if len(sc.config.CookiePath) > 0 {
			path = sc.config.CookiePath
		}
		cookie := http.Cookie{
			Name:     key,
			Value:    encoded,
			Path:     path,
			Secure:   sc.config.CookieSecure,
			HttpOnly: sc.config.CookieHTTPOnly,
			Expires:  payload.Expires,
			MaxAge:   int(cookieLifetime.Seconds()),
		}
		http.SetCookie(w, &cookie)
	} else {
		err = encErr
	}
	return
}

// Get retrieves and decodes a secure cookie.
func (sc *secureCookie) Get(r *http.Request, key string) (cookieValue, error) {
	cookie, err := r.Cookie(key)
	if err == nil {
		var value cookieValue
		err = sc.SC.Decode(key, cookie.Value, &value)
		if err != nil {
			return cookieValue{}, err
		}
		if value.Expires.Before(time.Now()) {
			return cookieValue{}, http.ErrNoCookie
		}
		return value, nil
	}
	return cookieValue{}, err
}
