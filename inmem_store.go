package auth

import "sync"

type inMemStore struct {
	storage map[string]storeValue
}

var singleton *inMemStore
var once sync.Once

func getStore() *inMemStore {
	once.Do(func() {
		store := inMemStore{}
		store.storage = make(map[string]storeValue)
		singleton = &store
	})
	return singleton
}

func (store *inMemStore) set(key string, value storeValue) {
	store.storage[key] = value
}

func (store *inMemStore) get(key string) (value storeValue, found bool) {
	value, found = store.storage[key]
	return
}

func (store *inMemStore) unset(key string) {
	delete(store.storage, key)
}

func (store *inMemStore) unsetAll(userID string) {
	for key, value := range store.storage {
		if value.UserID == userID {
			store.unset(key)
		}
	}
}
