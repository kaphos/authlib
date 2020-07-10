package authlib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	password := randStr(64)
	a := testObject()
	hash := a.HashPassword(HashPasswordOpts{Password: password})
	match, err := ComparePasswordAndHash(ComparePasswordOpts{
		password:    password,
		encodedHash: hash,
	})

	assert.Empty(t, err, "Error comparing password")
	assert.True(t, match, "Error matching password")

	hash = quickHash(password) // Run a quick hash also
	match, err = ComparePasswordAndHash(ComparePasswordOpts{
		password:    password,
		encodedHash: hash,
	})

	assert.Empty(t, err, "Error comparing password from quick hash")
	assert.True(t, match, "Error matching password from quick hash")
}
