package authlib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedisStore(t *testing.T) {
	store, err := createRedisStore(":6379", randStr(8))
	if assert.Empty(t, err, "unable to instantiate redis store") {
		key := randStr(64)
		value := randStr(64)
		store.set(key, storeValue{HashedToken: value})
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
			store.set(id+"-"+key, storeValue{HashedToken: value, UserID: id})
		}

		_, found = store.get(id + "-" + keys[0])
		assert.True(t, found, "Should be able to retrieve key")

		store.unsetAll(id)
		_, found = store.get(id + "-" + keys[0])
		assert.False(t, found, "Should not be able to retrieve key")
	}
}
