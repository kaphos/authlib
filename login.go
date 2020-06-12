package authlib

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/opentracing/opentracing-go"
)

func (a *Object) setCookie(key, token string, w http.ResponseWriter) (err error) {
	err = a.sc.Set(w, "auth", cookieValue{
		Key:   key,
		Token: token,
	}, a.config.ForcedTimeout)
	return
}

func (a *Object) setInMemStore(key, hashedToken, userID string) {
	getStore(a.config.RedisConn, a.config.RedisNamespace).set(key, storeValue{
		HashedToken: hashedToken,
		UserID:      userID,
		Expires:     time.Now().Add(a.config.IdleTimeout),   // Logs user out if they idle for more than 1 hour
		MaxExpiry:   time.Now().Add(a.config.ForcedTimeout), // User forced to log in after 3 days
	})
}

func (a *Object) saveLoginInStore(userID string) (key, token string) {
	// We prefix the key with user ID, to help with 'forget all' for Redis (can just do a wildcard search)
	key = userID + "-" + string(securecookie.GenerateRandomKey(32))
	token = string(securecookie.GenerateRandomKey(256))
	a.setInMemStore(key, quickHash(token), userID)
	return
}

// Saves a "login" for a given user ID
func (a *Object) saveLogin(opts saveLoginOpts) (err error) {
	if opts.spanContext != nil {
		span := opentracing.StartSpan("authlib-saveLogin", opentracing.ChildOf(opts.spanContext))
		defer span.Finish()
	}

	// Generate a key and token, and save it in the database first
	key, token := a.saveLoginInStore(opts.userID)

	// Build an encrypted cookie to store this key and token on the user side as well
	err = a.setCookie(key, token, opts.w)
	if err != nil {
		return
	}

	// If remember me flag is true, generate a cookie to save that credentials as well
	if opts.rmbMe {
		a.generateRmbMeCookie(opts.w, opts.userID)
	}
	return
}

// checkValidCookie checks if a provided cookie can be found in our
// in-mem storage, and if it has expired.
func (a *Object) checkValidCookie(opts cookieOpts) (userID string, valid bool) {
	if opts.spanContext != nil {
		span := opentracing.StartSpan("authlib-checkValidCookie", opentracing.ChildOf(opts.spanContext))
		defer span.Finish()
	}

	storedValue, found := a.store.get(opts.key)
	if !found {
		return
	}

	// Check if login session has expired
	if time.Now().After(storedValue.Expires) {
		return
	}

	// Check if the hashes match
	match, err := comparePasswordAndHash(comparePasswordOpts{
		password:    opts.token,
		encodedHash: storedValue.HashedToken,
	})
	if err != nil || !match {
		return
	}

	// Update expiry details
	storedValue.Expires = time.Now().Add(a.config.IdleTimeout)
	if storedValue.Expires.After(storedValue.MaxExpiry) {
		storedValue.Expires = storedValue.MaxExpiry
	}

	a.store.set(opts.key, storedValue)

	return storedValue.UserID, true
}
