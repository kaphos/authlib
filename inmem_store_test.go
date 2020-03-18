package authlib

import "testing"

func TestStore(t *testing.T) {
	store := getStore()
	key := "MY5byUoa#W^$aLZWwjODtR^8fLEw5NJgQOCj5brztWcT1%Jtpv!O6nAqPTAtvi3W"
	value := "JUf65nWCS!h$euA@N#RJLj1w!SyecwEY7IGNySF^IVFnWoh79&MJHSi56Xg1J@X2"
	store.set(key, storeValue{HashedToken: value})
	valueFound, found := store.get(key)
	if !found {
		t.Error("Could not retrieve key")
	} else if valueFound.HashedToken != value {
		t.Error("Wrong value retrieved")
	}

	store.unset(key)

	valueFound, found = store.get(key)
	if found {
		t.Error("Should not have been able to retrieve key")
	}
}
