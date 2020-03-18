package auth

import (
	"testing"
)

func TestDB(t *testing.T) {
	db := getDB(testDBPath)
	key := "7eOC1LVrXB6&v!2ijuEVH0I2ItF0SxH7mMtDEwA7*2HCq!w6%TUd7N*k%C2$P!q^"
	token := "Rhsq@9&G*0dZrySsI^VZg1y10gYz&kNG6j^@CpHmdqibk0M97yBD0LeQfPkJcc*9"
	userID := "1"
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
	} else if match, _ := comparePasswordAndHash(token, hashedToken); !match {
		t.Error("Wrong hashed token retrieved.")
	}

	db.RemoveSingle(key)
	db.RemoveAll(userID)
}
