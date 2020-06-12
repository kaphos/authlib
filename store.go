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
			getLogger().Info("Attempting to connect to Redis on " + redisConn)
			storeSingleton, err = createRedisStore(redisConn, redisNamespace)
			if err == nil {
				getLogger().Info("Successfully connected")
			} else {
				getLogger().Warn("Could not connect to Redis")
			}
		}
		if redisConn == "" || err != nil {
			storeSingleton = createMapStore()
			getLogger().Info("Using in-built map store")
		}
	})
	return storeSingleton
}
