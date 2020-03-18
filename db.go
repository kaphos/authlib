package authlib

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3" // SQL database driver
)

// Database - used to connect to the database
type database struct {
	Connected bool
	DB        *sql.DB
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
	database, _ := sql.Open("sqlite3", dbPath)
	stmt, _ := database.Prepare(`CREATE TABLE IF NOT EXISTS tokens (key TEXT PRIMARY KEY, token_hash TEXT, user_id TEXT)`)
	stmt.Exec()

	d.Connected = true
	d.DB = database
}

// Close the database connection
func (d *database) Close() {
	d.Connected = false
	d.DB.Close()
}

// Insert a new entry into the database.
func (d *database) Insert(key, hashedToken, userID string) (err error) {
	_, err = d.DB.Exec(`INSERT INTO tokens (key, token_hash, user_id) VALUES ($1, $2, $3)`, key, hashedToken, userID)
	return
}

// Fetch a user ID and hashed token, given a key.
func (d *database) Fetch(key string) (userID, hashedToken string, err error) {
	row := d.DB.QueryRow(`SELECT user_id, token_hash FROM tokens WHERE key = $1 LIMIT 1`, key)
	err = row.Scan(&userID, &hashedToken)
	return
}

// RemoveSingle removes a single entry from the database
// based on a given key. Used when a user wants to log out
// from a single session.
func (d *database) RemoveSingle(key string) {
	d.DB.Exec(`DELETE FROM tokens WHERE key = $1`, key)
}

// RemoveAll removes all entries from the database
// based on a given user ID. Used when a user wants to log out
// from all sessions.
func (d *database) RemoveAll(userID string) {
	d.DB.Exec(`DELETE FROM tokens WHERE user_id = $1`, userID)
}
