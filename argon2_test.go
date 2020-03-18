package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "KE#Ru%J2Ok%UYOXUdouy7zWt4jbaZPS6ZXUgBYLLh10ho!7s6v4NlOf@S^fDh*nm"
	a := testObject()
	hash := a.HashPassword(password)
	match, err := comparePasswordAndHash(password, hash)
	if err != nil {
		t.Error("Error comparing password:", err)
	} else if match != true {
		t.Error("Error matching password")
	}

	hash = quickHash(password) // Run a quick hash also
	match, err = comparePasswordAndHash(password, hash)
	if err != nil {
		t.Error("Error comparing password from quick hash:", err)
	} else if match != true {
		t.Error("Error matching password from quick hash")
	}
}
