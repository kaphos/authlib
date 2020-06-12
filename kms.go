package authlib

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"

	"github.com/gorilla/securecookie"
)

// keyManagementStore holds all the relevant keys that is used by the program in runtime.
type keyManagementStore struct {
	CookiesHash  []byte
	CookiesBlock []byte
}

var kmsSingleton *keyManagementStore
var kmsOnce sync.Once

// getKMS returns the program's key management store.
// On first run, will attempt to fetch the keys from the path.
// If not found, will generate a new set and save it.
func getKMS(configPath string) *keyManagementStore {
	kmsOnce.Do(func() {
		var kms keyManagementStore
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			// Generate keys
			kms = createKMSFile(configPath)
		} else {
			// Load keys from disk
			kms = loadKMSFile(configPath)
		}
		kmsSingleton = &kms
	})
	return kmsSingleton
}

func createKMSFile(configPath string) (kms keyManagementStore) {
	getLogger().Info(configPath + " not found. Generating new file.")
	kms.CookiesHash = securecookie.GenerateRandomKey(64)
	kms.CookiesBlock = securecookie.GenerateRandomKey(32)

	jsonBody, _ := json.Marshal(kms)

	// Encode to base64 and write to disk
	jsonBody = []byte(base64.RawStdEncoding.EncodeToString(jsonBody))
	ioutil.WriteFile(configPath, jsonBody, 0600)
	getLogger().Info("Generated keys saved at " + configPath)
	return
}

func loadKMSFile(configPath string) (kms keyManagementStore) {
	file, err := os.Open(configPath)
	if err != nil {
		getLogger().Fatal("Could not open " + configPath)
	}

	defer file.Close()

	// Decode from base64
	fileContents, _ := ioutil.ReadAll(file)
	fileContents, err = base64.RawStdEncoding.DecodeString(string(fileContents))
	if err != nil {
		getLogger().Fatal("Could not decode JSON.")
	}

	// Unmarshal into struct
	err = json.Unmarshal(fileContents, &kms)
	if err != nil {
		getLogger().Fatal("Could not parse config file.")
	} else {
		getLogger().Info("Loaded keys from " + configPath)
	}

	return
}
