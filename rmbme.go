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
func (a *Object) checkRmbMeInDB(cookieValue cookiePayload) (userID string, err error) {
	var storedHash string
	userID, storedHash, err = a.db.Fetch(cookieValue.Key)
	if err != nil {
		return
	}

	match, err := comparePasswordAndHash(cookieValue.Token, storedHash)
	if err != nil || !match {
		// Invalidate database entry
		err = errors.New("Invalid token value")
		a.db.RemoveSingle(cookieValue.Key)
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
	return a.sc.Set(w, "rmbme", cookiePayload{
		Key:   key,
		Token: token,
	}, a.config.RmbMeTimeout)
}

func (a *Object) checkRmbMeCookie(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	var cookieValue cookiePayload
	cookieValue, err = a.sc.Get(r, "rmbme")
	if err == nil {
		userID, err = a.checkRmbMeInDB(cookieValue)
		if err == nil {
			// Valid rmb me token
			err = a.saveLogin(userID, true, w)
			if err == nil {
				a.generateRmbMeCookie(w, userID)
			}
		}
	}
	return
}
