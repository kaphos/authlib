package authlib

import "time"

// Config contains the package parameters that can be tuned
type Config struct {
	KMSPath        string        // Where the generated keys should be stored (for using securecookies)
	DBPath         string        // Where the sqlite3 database should be stored
	IdleTimeout    time.Duration // How long they can be idle before they're logged out
	ForcedTimeout  time.Duration // How long the session can persist before they're asked to log in again
	RmbMeTimeout   time.Duration // How long the "Remember Me" token is valid for
	HashMemory     uint32        // Number of megabytes that argon2 should use
	HashIterations uint32        // Number of iterations that argon2 should use
}
