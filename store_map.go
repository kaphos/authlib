package authlib

import "sync"

type mapStore struct {
	storage map[string]storeValue
	mux     *sync.Mutex
}

func createMapStore() mapStore {
	return mapStore{
		storage: make(map[string]storeValue),
		mux:     &sync.Mutex{},
	}
}

func (store mapStore) set(key string, value storeValue) {
	store.mux.Lock()
	defer store.mux.Unlock()
	store.storage[key] = value
}

func (store mapStore) get(key string) (value storeValue, found bool) {
	value, found = store.storage[key]
	return
}

func (store mapStore) unset(key string) {
	store.mux.Lock()
	defer store.mux.Unlock()
	delete(store.storage, key)
}

func (store mapStore) unsetAll(userID string) {
	for key, value := range store.storage {
		if value.UserID == userID {
			store.unset(key)
		}
	}
}
