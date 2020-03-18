package auth

import (
	"os"
	"testing"
	"time"
)

const testDBPath = "test_db"
const testKMSConfigPath = "test_kms"

func testObject() *Object {
	config := Config{
		KMSPath:        testKMSConfigPath,
		DBPath:         testDBPath,
		IdleTimeout:    time.Minute,
		ForcedTimeout:  time.Minute * 3,
		RmbMeTimeout:   time.Minute * 5,
		HashIterations: 7,
		HashMemory:     48,
	}
	return New(config)
}

func TestMain(m *testing.M) {
	code := m.Run()
	getDB(testDBPath).Close()
	os.Remove(testDBPath)
	os.Remove(testKMSConfigPath)
	os.Exit(code)
}
