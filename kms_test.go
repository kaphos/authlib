package authlib

import (
	"testing"
)

func TestKMS(t *testing.T) {
	createKMSFile(testKMSConfigPath) // Test file creation
	loadKMSFile(testKMSConfigPath)   // Test file loading
	getKMS(testKMSConfigPath)        // Test singleton function
}
