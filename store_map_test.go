package authlib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMapStore(t *testing.T) {
	store := createMapStore()
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

	// Test unset all
	id := randStr(64)
	keys := make([]string, 0)
	for i := 0; i < 5; i++ {
		key := randStr(64)
		keys = append(keys, key)
		value := randStr(64)
		store.set(key, storeValue{
			HashedToken: value,
			UserID:      id,
			MaxExpiry:   time.Now().Add(time.Minute),
		})
	}

	_, found = store.get(keys[0])
	assert.True(t, found, "Should be able to retrieve key")

	store.unsetAll(id)
	_, found = store.get(keys[0])
	assert.False(t, found, "Should not be able to retrieve key")
}
