package authlib

// import (
// 	"bytes"
// 	"encoding/gob"
// 	"time"

// 	"github.com/gomodule/redigo/redis"
// )

// type redisStore struct {
// 	pool      *redis.Pool
// 	namespace string
// }

// func encodeGob(v storeValue) []byte {
// 	var buf bytes.Buffer
// 	enc := gob.NewEncoder(&buf)
// 	err := enc.Encode(v)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return buf.Bytes()
// }

// func decodeGob(b []byte, result *storeValue) {
// 	buf := bytes.NewBuffer(b)
// 	enc := gob.NewDecoder(buf)
// 	err := enc.Decode(result)
// 	if err != nil {
// 		panic(err)
// 	}
// }

// func createRedisStore(connStr, namespace string) (redisStore, error) {
// 	pool := &redis.Pool{
// 		MaxIdle:     3,
// 		IdleTimeout: 5 * time.Second,
// 		Wait:        true,
// 		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", connStr, redis.DialConnectTimeout(1*time.Second)) },
// 	}

// 	if _, err := pool.Get().Do("PING"); err != nil {
// 		return redisStore{}, err
// 	}

// 	return redisStore{pool: pool, namespace: namespace}, nil
// }

// func (store redisStore) formatKey(key string) string {
// 	return store.namespace + "#" + key
// }

// func (store redisStore) set(key string, value storeValue) {
// 	conn := store.pool.Get()
// 	defer conn.Close()
// 	conn.Do("SET", store.formatKey(key), encodeGob(value))
// 	conn.Do("EXPIREAT", store.formatKey(key), value.MaxExpiry.Unix())
// }

// func (store redisStore) get(key string) (value storeValue, found bool) {
// 	conn := store.pool.Get()
// 	defer conn.Close()
// 	encodedVal, err := redis.Bytes(conn.Do("GET", store.formatKey(key)))
// 	if encodedVal == nil || err != nil {
// 		return storeValue{}, false
// 	}
// 	decodeGob(encodedVal, &value)
// 	return value, true
// }

// func (store redisStore) unset(key string) {
// 	conn := store.pool.Get()
// 	defer conn.Close()
// 	conn.Do("DEL", store.formatKey(key))
// }

// func (store redisStore) unsetAll(userID string) {
// 	conn := store.pool.Get()
// 	defer conn.Close()
// 	keys, err := redis.Strings(conn.Do("KEYS", store.formatKey(userID+"-*")))
// 	if err != nil {
// 		return
// 	}
// 	s := make([]interface{}, len(keys))
// 	for i, v := range keys {
// 		s[i] = v
// 	}
// 	conn.Do("DEL", s...)
// }
