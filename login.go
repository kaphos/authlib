package auth

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

func (a *Object) setCookie(key, token string, w http.ResponseWriter) (err error) {
	err = a.sc.Set(w, "auth", cookiePayload{
		Key:   key,
		Token: token,
	}, a.config.ForcedTimeout)
	return
}

func (a *Object) setInMemStore(key, hashedToken, userID string) {
	getStore().set(key, storeValue{
		HashedToken: hashedToken,
		UserID:      userID,
		Expires:     time.Now().Add(a.config.IdleTimeout),   // Logs user out if they idle for more than 1 hour
		MaxExpiry:   time.Now().Add(a.config.ForcedTimeout), // User forced to log in after 3 days
	})
}

func (a *Object) saveLoginInDB(userID string) (key, token string) {
	key = string(securecookie.GenerateRandomKey(32))
	token = string(securecookie.GenerateRandomKey(256))
	a.setInMemStore(key, quickHash(token), userID)
	return
}

// Saves a "login" for a given user ID
func (a *Object) saveLogin(userID string, rmbMe bool, w http.ResponseWriter) (err error) {
	// Generate a key and token, and save it in the database first
	key, token := a.saveLoginInDB(userID)

	// Build an encrypted cookie to store this key and token on the user side as well
	err = a.setCookie(key, token, w)
	if err != nil {
		return
	}

	// If remember me flag is true, generate a cookie to save that credentials as well
	if rmbMe {
		a.generateRmbMeCookie(w, userID)
	}
	return
}

// checkValidCookie checks if a provided cookie can be found in our
// in-mem storage, and if it has expired.
func (a *Object) checkValidCookie(cookieValue cookiePayload) (userID string, valid bool) {
	storedValue, found := a.store.get(cookieValue.Key)
	if !found {
		return
	}

	// Check if login session has expired
	if time.Now().After(storedValue.Expires) {
		return
	}

	// Check if the hashes match
	match, err := comparePasswordAndHash(cookieValue.Token, storedValue.HashedToken)
	if err != nil || !match {
		return
	}

	// Update expiry details
	storedValue.Expires = time.Now().Add(a.config.IdleTimeout)
	if storedValue.Expires.After(storedValue.MaxExpiry) {
		storedValue.Expires = storedValue.MaxExpiry
	}

	a.store.set(cookieValue.Key, storedValue)

	return storedValue.UserID, true
}
