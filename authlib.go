package authlib

import (
	"errors"

	"github.com/opentracing/opentracing-go"
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
func (a *Object) HashPassword(opts HashPasswordOpts) (hash string) {
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-hashPassword", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
	}

	hashMemory := a.config.HashMemory
	hashIterations := a.config.HashIterations
	if hashMemory == 0 {
		hashMemory = 48
	}
	if hashIterations == 0 {
		hashIterations = 7
	}
	return argon2Hash(opts.Password, hashMemory, hashIterations)
}

// AttemptLogin for a given user. Called when trying to log in.
// Takes in the provided password as well as
// the password hash, and performs the comparison. If invalid, will throw an error.
// If accepted, it will manage the respective cookies.
func (a *Object) AttemptLogin(opts AttemptLoginOpts) (err error) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-attemptLogin", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	match, compareError := comparePasswordAndHash(comparePasswordOpts{
		password:    opts.ProvidedPassword,
		encodedHash: opts.PasswordHash,
	})
	if match {
		// Perform login
		err = a.saveLogin(saveLoginOpts{
			userID:      opts.ID,
			rmbMe:       opts.RmbMe,
			w:           opts.HTTPWriter,
			spanContext: spanContext,
		})
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
func (a *Object) CheckLogin(opts HTTPOpts) (userID string, valid bool) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-checkLogin", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	cookieOptsValue, err := a.sc.Get(opts.HTTPRequest, "auth")
	cookieOptsValue.spanContext = spanContext
	if err == nil {
		// Check if key is in our in-mem store
		userID, valid = a.checkValidCookie(cookieOptsValue)
		if !valid {
			// Not valid
			// Check to see if rmb me cookie is valid
			userID, err = a.checkRmbMeCookie(opts.HTTPWriter, opts.HTTPRequest)
			if err == nil {
				err = a.saveLogin(saveLoginOpts{
					userID:      userID,
					rmbMe:       true,
					w:           opts.HTTPWriter,
					spanContext: spanContext,
				})
				if err == nil {
					valid = true
				}
			}
		}
	}

	return
}

// Logout clears out the relevant cookies on the user side,
// while also removing the respective data on the server side.
func (a *Object) Logout(opts HTTPOpts) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-logout", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	cookieOptsValue, err := a.sc.Get(opts.HTTPRequest, "auth")
	if err == nil {
		a.store.unset(cookieOptsValue.key)
	}
	a.sc.Set(opts.HTTPWriter, "auth", cookieOpts{}, 0)

	// Clear remember me also, if it exists
	cookieOptsValue, err = a.sc.Get(opts.HTTPRequest, "rmbme")
	cookieOptsValue.spanContext = spanContext
	if err == nil {
		a.sc.Set(opts.HTTPWriter, "rmbme", cookieOpts{}, 0)
		a.db.RemoveSingle(cookieOptsValue.key)
	}
}

// LogoutAll removes all stored tokens in the database, and also
// invalidates the current login session
func (a *Object) LogoutAll(opts HTTPOpts) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-logoutAll", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	cookieOptsValue, err := a.sc.Get(opts.HTTPRequest, "auth")
	cookieOptsValue.spanContext = spanContext
	if err == nil {
		userID, valid := a.checkValidCookie(cookieOptsValue)
		if valid {
			a.db.RemoveAll(userID)
			a.store.unsetAll(userID)
		}
	}
	a.Logout(opts)
}
