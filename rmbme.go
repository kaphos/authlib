package authlib

import (
	"errors"
	"net/http"

	"github.com/gorilla/securecookie"
)

// Generate a random key and token, and store it to the database first.
func (a *Object) generateRmbMe(userID string) (key, token string, err error) {
	key = string(securecookie.GenerateRandomKey(64))
	token = string(securecookie.GenerateRandomKey(512))
	err = a.db.Insert(key, quickHash(token), userID)
	return
}

// Checks if a given cookie payload (token & key) matches what we have in the database.
func (a *Object) checkRmbMeInDB(cookieOptsValue cookieOpts) (userID string, err error) {
	var storedHash string
	userID, storedHash, err = a.db.Fetch(cookieOptsValue.key)
	if err != nil || userID == "" {
		// Either an error occurred, or no user was found
		return
	}

	match, err := ComparePasswordAndHash(ComparePasswordOpts{
		Password:    cookieOptsValue.token,
		EncodedHash: storedHash,
	})

	if err != nil || !match {
		// Invalidate database entry
		err = errors.New("Invalid token value")
		a.db.RemoveSingle(cookieOptsValue.key)
		return
	}
	return
}

func (a *Object) generateRmbMeCookie(w http.ResponseWriter, userID string) error {
	key, token, err := a.generateRmbMe(userID) // Generate key & token, and store to database
	if err != nil {
		return err
	}

	// Then take resulting values to save as secure cookie
	return a.sc.Set(w, "rmbme", cookieValue{
		Key:   key,
		Token: token,
	}, a.config.RmbMeTimeout)
}

func (a *Object) checkRmbMeCookie(opts HTTPOpts) (userID string, err error) {
	cookieObj, err := a.sc.Get(opts.HTTPRequest, "rmbme")
	if err == nil {
		userID, err = a.checkRmbMeInDB(cookieOpts{
			key:         cookieObj.Key,
			token:       cookieObj.Token,
			spanContext: opts.SpanContext,
		})
		if err == nil {
			// Valid rmb me token
			err = a.saveLogin(saveLoginOpts{
				userID: userID,
				rmbMe:  true,
				w:      opts.HTTPWriter,
			})
			if err == nil {
				a.generateRmbMeCookie(opts.HTTPWriter, userID)
			}
		}
	}
	return
}
