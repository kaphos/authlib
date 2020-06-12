package authlib

import (
	"time"
)

// Config contains the package parameters that can be tuned
type Config struct {
	RedisConn      string        // Connection string for Redis, if applicable. Leaving it blank will cause it to default to use in-mem map storage
	RedisNamespace string        // Namespace to use to prefix keys in Redis
	KMSPath        string        // Where the generated secure cookie keys should be stored
	DBPath         string        // Where the sqlite3 database should be stored (for rmb me)
	IdleTimeout    time.Duration // How long they can be idle before they're logged out
	ForcedTimeout  time.Duration // How long the session can persist before they're asked to log in again
	RmbMeTimeout   time.Duration // How long the "Remember Me" token is valid for
	HashMemory     uint32        // Number of megabytes that argon2 should use. Defaults to 48.
	HashIterations uint32        // Number of iterations that argon2 should use. Defaults to 7.
	CookiePath     string        // Path of cookie. Defaults to "/"
	CookieSecure   bool          // Whether to use secure cookies
	CookieHTTPOnly bool          // Whether to only http
}
