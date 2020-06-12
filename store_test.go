package authlib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStore(t *testing.T) {
	key := randStr(64)
	value := randStr(64)

	getStore("localhost:6379", "").set(key, storeValue{
		HashedToken: value,
		MaxExpiry:   time.Now().Add(time.Minute),
	})
	storedValue, found := getStore("localhost:6379", "").get(key)
	assert.True(t, found, "Not found")
	assert.Equal(t, value, storedValue.HashedToken, "Wrong value")
}
