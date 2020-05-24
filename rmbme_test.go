package authlib

import "testing"

func TestGenerateRmbMe(t *testing.T) {
	userID := "34"
	a := testObject()

	key, token, err := a.generateRmbMe(userID)
	if err != nil {
		t.Error("Error generating rmb me token:", err)
	}

	userIDFound, err := a.checkRmbMeInDB(cookieOpts{
		key:   key,
		token: token,
	})

	if err != nil {
		t.Error("Error checking rmb me in db:", err)
	} else if userID != userIDFound {
		t.Error("Wrong user ID retrieved")
	}

	_, err = a.checkRmbMeInDB(cookieOpts{
		key:   key,
		token: token + token,
	})

	if err == nil {
		t.Error("Should have invalidated with wrong token")
	}
}
