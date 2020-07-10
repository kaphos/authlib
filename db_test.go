package authlib

import (
	"testing"
)

func TestDB(t *testing.T) {
	db := getDB(testDBPath)
	key := randStr(64)
	token := randStr(64)
	userID := randStr(64)
	err := db.Insert(key, quickHash(token), userID)
	db.Insert(key+key, quickHash(token), userID)
	if err != nil {
		t.Error("Could not insert data:", err)
	}

	fetchedID, hashedToken, err := db.Fetch(key)
	if err != nil {
		t.Error("Could not fetch data:", err)
	} else if userID != fetchedID {
		t.Errorf("Wrong user ID retrieved. Expected %s, got %s", userID, fetchedID)
	} else if match, _ := ComparePasswordAndHash(ComparePasswordOpts{
		Password:    token,
		EncodedHash: hashedToken,
	}); !match {
		t.Error("Wrong hashed token retrieved.")
	}

	db.RemoveSingle(key)
	db.RemoveAll(userID)
}
