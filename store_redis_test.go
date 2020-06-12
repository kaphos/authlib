package authlib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRedisStore(t *testing.T) {
	store, err := createRedisStore(":6379", randStr(8))
	defer store.conn.Close()
	if assert.Empty(t, err, "unable to instantiate redis store") {
		key := randStr(64)
		value := randStr(64)
		store.set(key, storeValue{
			HashedToken: value,
			MaxExpiry:   time.Now().Add(time.Minute),
		})
		valueFound, found := store.get(key)
		if !found {
			t.Error("Could not retrieve key")
		} else if valueFound.HashedToken != value {
			t.Error("Wrong value retrieved")
		}

		store.unset(key)

		valueFound, found = store.get(key)
		assert.False(t, found, "Should not have been able to retrieve key")

		id := randStr(64)
		keys := make([]string, 0)
		for i := 0; i < 5; i++ {
			key := randStr(64)
			keys = append(keys, key)
			value := randStr(64)
			store.set(id+"-"+key, storeValue{
				HashedToken: value,
				UserID:      id,
				MaxExpiry:   time.Now().Add(time.Minute),
			})
		}

		_, found = store.get(id + "-" + keys[0])
		assert.True(t, found, "Should be able to retrieve key")

		store.unsetAll(id)
		_, found = store.get(id + "-" + keys[0])
		assert.False(t, found, "Should not be able to retrieve key")

		// Test expiry
		store.set(key, storeValue{
			HashedToken: value,
			MaxExpiry:   time.Now().Add(-time.Minute),
		})
		_, found = store.get(key)
		assert.False(t, found, "Should not have been able to retrieve token")
	}
}

func TestMultipleRedisStores(t *testing.T) {
	store1, err1 := createRedisStore(":6379", randStr(8))
	assert.Empty(t, err1, "Error creating redis store 1")
	store2, err2 := createRedisStore(":6379", randStr(8))
	assert.Empty(t, err2, "Error creating redis store 2")

	defer store1.conn.Close()
	defer store2.conn.Close()

	key := randStr(64)
	value := randStr(64)

	store1.set(key, storeValue{
		HashedToken: value,
		MaxExpiry:   time.Now().Add(time.Minute),
	})

	_, found := store1.get(key)
	assert.True(t, found, "Could not retrieve key from correct store")
	_, found = store2.get(key)
	assert.False(t, found, "Should not have retrieved key from wrong store")
}
