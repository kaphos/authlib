package authlib

import "sync"

type storeInterface interface {
	set(string, storeValue)
	get(string) (storeValue, bool)
	unset(string)
	unsetAll(string)
}

type storeType struct {
	store storeInterface
}

var storeSingleton storeInterface
var storeOnce sync.Once

func getStore(redisConn, redisNamespace string) storeInterface {
	storeOnce.Do(func() {
		var err error
		if redisConn != "" {
			// Attempt to connect to Redis
			storeSingleton, err = createRedisStore(redisConn, redisNamespace)
		}
		if redisConn == "" || err != nil {
			storeSingleton = createMapStore()
		}
	})
	return storeSingleton
}
