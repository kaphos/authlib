package authlib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRmbMe(t *testing.T) {
	userID := randStr(64)
	a := testObject()

	key, token, err := a.generateRmbMe(userID)
	assert.Empty(t, err, "Error generating rmb me token")

	userIDFound, err := a.checkRmbMeInDB(cookieOpts{
		key:   key,
		token: token,
	})
	assert.Empty(t, err, "Error checking rmb me in db")
	assert.Equal(t, userID, userIDFound, "Wrong user ID retrieved")

	_, err = a.checkRmbMeInDB(cookieOpts{
		key:   key,
		token: token + token,
	})
	assert.NotEmpty(t, err, "Should have invalidated with wrong token")
}
