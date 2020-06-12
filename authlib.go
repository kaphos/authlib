package authlib

import (
	"net/http"

	"github.com/opentracing/opentracing-go"
)

// Object contains the initialised config, along with several helper modules
// used to perform the auth methods, such as a secure cookie object, a key management store,
// and a database.
type Object struct {
	config Config
	sc     *secureCookie
	store  storeInterface
	kms    *keyManagementStore
	db     *database
}

// New creates a Object that can then be used to perform authentication/authorisation methods.
// Takes in a Config object, highlighting paths for the database & KMS store, as well as parameters
// for timeouts & argon2 hashing.
func New(config Config) *Object {
	redisConn := config.RedisConn // convert to empty string if nil
	redisNamespace := config.RedisNamespace

	authObj := Object{
		config: config,
		sc:     getSC(config),
		store:  getStore(redisConn, redisNamespace),
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
// Takes in the provided password as well as the password hash,
// and performs the comparison. If the password doesn't match
// the hash, it will return ok as false. If accepted, it will
// manage the respective cookies.
// ok = true: Logged in
// ok = false, err = nil: Wrong password
// ok = false, err != nil: An error occurred
func (a *Object) AttemptLogin(opts AttemptLoginOpts) (ok bool, err error) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-attemptLogin", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	match, err := comparePasswordAndHash(comparePasswordOpts{
		password:    opts.ProvidedPassword,
		encodedHash: opts.PasswordHash,
	})
	if match {
		// Password matches hash. Perform login.
		err = a.saveLogin(saveLoginOpts{
			userID:      opts.ID,
			rmbMe:       opts.RmbMe,
			w:           opts.HTTPWriter,
			spanContext: spanContext,
		})
		ok = (err == nil)
	}
	return
}

// CheckLogin checks if a user has a valid auth cookie.
// Called when verifying authentication for an endpoint.
func (a *Object) CheckLogin(opts HTTPOpts) (userID string, valid bool, err error) {
	var spanContext opentracing.SpanContext
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-checkLogin", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
		spanContext = span.Context()
	}

	cookieObj, err := a.sc.Get(opts.HTTPRequest, "auth")
	if err != nil {
		// Check if error was due to cookie not being found
		if err == http.ErrNoCookie {
			return "", false, nil
		}
		return "", false, err
	}

	// Check if key is in our in-mem store
	userID, valid = a.checkValidCookie(cookieOpts{
		key:         cookieObj.Key,
		token:       cookieObj.Token,
		spanContext: spanContext,
	})
	if !valid {
		// Not valid
		// Check to see if rmb me cookie is valid
		userID, err = a.checkRmbMeCookie(opts)
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

	return
}

// Logout clears out the relevant cookies on the user side,
// while also removing the respective data on the server side.
func (a *Object) Logout(opts HTTPOpts) {
	if opts.SpanContext != nil {
		span := opentracing.StartSpan("authlib-logout", opentracing.ChildOf(opts.SpanContext))
		defer span.Finish()
	}

	cookieObj, err := a.sc.Get(opts.HTTPRequest, "auth")
	if err == nil {
		// Remove item from in-mem storage
		a.store.unset(cookieObj.Key)
	}
	// Remove cookie from the user side
	a.sc.Set(opts.HTTPWriter, "auth", cookieValue{}, -1)

	// Clear remember me also, if it exists
	cookieObj, err = a.sc.Get(opts.HTTPRequest, "rmbme")
	if err == nil {
		a.sc.Set(opts.HTTPWriter, "rmbme", cookieValue{}, -1)
		a.db.RemoveSingle(cookieObj.Key)
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

	cookieObj, err := a.sc.Get(opts.HTTPRequest, "auth")
	if err == nil {
		userID, valid := a.checkValidCookie(cookieOpts{
			key:         cookieObj.Key,
			token:       cookieObj.Token,
			spanContext: spanContext,
		})
		if valid {
			a.db.RemoveAll(userID)
			a.store.unsetAll(userID)
		}
	}
	a.Logout(opts)
}
