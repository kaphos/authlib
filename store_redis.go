package authlib

import (
	"bytes"
	"encoding/gob"

	"github.com/gomodule/redigo/redis"
)

type redisStore struct {
	conn      redis.Conn
	namespace string
}

func encodeGob(v storeValue) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func decodeGob(b []byte, result *storeValue) {
	buf := bytes.NewBuffer(b)
	enc := gob.NewDecoder(buf)
	err := enc.Decode(result)
	if err != nil {
		panic(err)
	}
}

func createRedisStore(connStr, namespace string) (redisStore, error) {
	c, err := redis.Dial("tcp", connStr)
	if err != nil {
		return redisStore{}, err
	}
	return redisStore{conn: c, namespace: namespace}, nil
}

func (store redisStore) formatKey(key string) string {
	return store.namespace + "#" + key
}

func (store redisStore) set(key string, value storeValue) {
	store.conn.Do("SET", store.formatKey(key), encodeGob(value))
	store.conn.Do("EXPIREAT", store.formatKey(key), value.MaxExpiry.Unix())
}

func (store redisStore) get(key string) (value storeValue, found bool) {
	encodedVal, err := redis.Bytes(store.conn.Do("GET", store.formatKey(key)))
	if encodedVal == nil || err != nil {
		return storeValue{}, false
	}
	decodeGob(encodedVal, &value)
	return value, true
}

func (store redisStore) unset(key string) {
	store.conn.Do("DEL", store.formatKey(key))
}

func (store redisStore) unsetAll(userID string) {
	keys, err := redis.Strings(store.conn.Do("KEYS", store.formatKey(userID+"-*")))
	if err != nil {
		return
	}
	s := make([]interface{}, len(keys))
	for i, v := range keys {
		s[i] = v
	}
	store.conn.Do("DEL", s...)
}
