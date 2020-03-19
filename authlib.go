package authlib

import (
	"errors"
	"log"
	"net/http"
)

// Object contains the initialised config, along with several helper modules
// used to perform the auth methods, such as a secure cookie object, a key management store,
// and a database.
type Object struct {
	config Config
	sc     *secureCookie
	store  *inMemStore
	kms    *keyManagementStore
	db     *database
}

// New creates a Object that can then be used to perform authentication/authorisation methods.
// Takes in a Config object, highlighting paths for the database & KMS store, as well as parameters
// for timeouts & argon2 hashing.
func New(config Config) *Object {
	authObj := Object{
		config: config,
		sc:     getSC(config),
		store:  getStore(),
		kms:    getKMS(config.KMSPath),
		db:     getDB(config.DBPath),
	}
	return &authObj
}

// HashPassword using argon2
func (a *Object) HashPassword(password string) (hash string) {
	return argon2Hash(password, a.config.HashMemory, a.config.HashIterations)
}

// AttemptLogin for a given user. Called when trying to log in.
// Takes in the provided password as well as
// the password hash, and performs the comparison. If invalid, will throw an error.
// If accepted, it will manage the respective cookies.
func (a *Object) AttemptLogin(w http.ResponseWriter, payload LoginPayload) (err error) {
	match, compareError := comparePasswordAndHash(payload.ProvidedPassword, payload.PasswordHash)
	if match {
		// Perform login
		err = a.saveLogin(payload.ID, payload.RmbMe, w)
	} else {
		if compareError != nil {
			err = compareError
		} else {
			err = errors.New("Could not authenticate")
		}
	}
	return
}

// CheckLogin checks if a user has a valid auth cookie.
// Called when verifying authentication for an endpoint.
func (a *Object) CheckLogin(w http.ResponseWriter, r *http.Request) (userID string, valid bool) {
	cookieValue, err := a.sc.Get(r, "auth")
	if err == nil {
		// Check if key is in our in-mem store
		userID, valid = a.checkValidCookie(cookieValue)
		if !valid {
			// Not valid
			// Check to see if rmb me cookie is valid
			userID, err = a.checkRmbMeCookie(w, r)
			if err == nil {
				err = a.saveLogin(userID, true, w)
				if err == nil {
					valid = true
				}
			}
		}
	}
	log.Println("Could not decrypt cookie")
	return
}

// Logout clears out the relevant cookies on the user side,
// while also removing the respective data on the server side.
func (a *Object) Logout(w http.ResponseWriter, r *http.Request) {
	cookieValue, err := a.sc.Get(r, "auth")
	if err == nil {
		a.store.unset(cookieValue.Key)
	}
	a.sc.Set(w, "auth", cookiePayload{}, 0)

	// Clear remember me also, if it exists
	cookieValue, err = a.sc.Get(r, "rmbme")
	if err == nil {
		a.sc.Set(w, "rmbme", cookiePayload{}, 0)
		a.db.RemoveSingle(cookieValue.Key)
	}
}

// LogoutAll removes all stored tokens in the database, and also
// invalidates the current login session
func (a *Object) LogoutAll(w http.ResponseWriter, r *http.Request) {
	cookieValue, err := a.sc.Get(r, "auth")
	if err == nil {
		userID, valid := a.checkValidCookie(cookieValue)
		if valid {
			a.db.RemoveAll(userID)
			a.store.unsetAll(userID)
		}
	}
	a.Logout(w, r)
}
