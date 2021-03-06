package authlib

import (
	"testing"

	"github.com/gorilla/securecookie"
)

func TestSetInMemStore(t *testing.T) {
	key := string(securecookie.GenerateRandomKey(32))
	token := string(securecookie.GenerateRandomKey(256))
	userID := randStr(64)
	testObject().setInMemStore(key, token, userID)
}

func TestCheckLoginCookie(t *testing.T) {
	// Set up test
	key := string(securecookie.GenerateRandomKey(32))
	token := string(securecookie.GenerateRandomKey(256))
	userID := randStr(64)
	a := testObject()
	a.setInMemStore(key, quickHash(token), userID)

	// Test for valid user
	userFound, valid := a.checkValidCookie(cookieOpts{
		key:   key,
		token: token,
	})
	if !valid {
		t.Error("Login should have been valid, but was not accepted")
	} else if userFound != userID {
		t.Error("User found had a different ID from what was expected")
	}

	// Test for wrong token
	userFound, valid = a.checkValidCookie(cookieOpts{
		key:   key,
		token: token + token,
	})
	if valid {
		t.Error("Login should not have been accepted")
	}
}

func TestSaveLoginInDB(t *testing.T) {
	a := testObject()
	a.saveLoginInStore("1")
}
