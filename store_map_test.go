package authlib

import (
	"testing"

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
}
