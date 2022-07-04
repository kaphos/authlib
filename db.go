package authlib

import (
	"sync"
)

// Database - used to connect to the database
type database struct {
	Connected bool
	DB        map[string]Store
}

type Store struct {
	UserID    string
	TokenHash string
}

var dbSingleton *database
var dbOnce sync.Once

// getDB returns the dbSingleton database instance
func getDB(dbPath string) *database {
	dbOnce.Do(func() {
		db := database{}
		db.init(dbPath)
		dbSingleton = &db
	})
	return dbSingleton
}

// Init - Initialises the database object
func (d *database) init(dbPath string) {
	d.Connected = true
	d.DB = make(map[string]Store)
}

// Close the database connection
func (d *database) Close() {
	d.Connected = false
}

// Insert a new entry into the database.
func (d *database) Insert(key, hashedToken, userID string) (err error) {
	d.DB[key] = Store{UserID: userID, TokenHash: hashedToken}
	return nil
}

// Fetch a user ID and hashed token, given a key.
func (d *database) Fetch(key string) (userID, hashedToken string, err error) {
	result, ok := d.DB[key]
	if !ok {
		return
	}

	return result.UserID, result.TokenHash, nil
}

// RemoveSingle removes a single entry from the database
// based on a given key. Used when a user wants to log out
// from a single session.
func (d *database) RemoveSingle(key string) {
	delete(d.DB, key)
}

// RemoveAll removes all entries from the database
// based on a given user ID. Used when a user wants to log out
// from all sessions.
func (d *database) RemoveAll(userID string) {
	// d.DB.Exec(`DELETE FROM tokens WHERE user_id = $1`, userID)
}
