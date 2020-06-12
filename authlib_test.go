package authlib

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testDBPath = "test_db"
const testKMSConfigPath = "test_kms"

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getCookie(recorder *httptest.ResponseRecorder, cookieName string) (*http.Cookie, error) {
	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	return request.Cookie(cookieName)
}

func testObject() *Object {
	config := Config{
		RedisConn:      "localhost:6379",
		RedisNamespace: randStr(32),
		KMSPath:        testKMSConfigPath,
		DBPath:         testDBPath,
		IdleTimeout:    time.Second * 5,
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

func TestCorrectAttemptLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObject().HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObject().AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            false,
	})

	assert.True(t, ok, "Login was not accepted")
	assert.Empty(t, err, "An error occurred while logging in")

	_, err = getCookie(recorder, "auth")
	assert.Empty(t, err, "Cookie was not set")
}

func TestWrongAttemptLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObject().HashPassword(HashPasswordOpts{Password: randStr(63)})

	ok, err := testObject().AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            false,
	})

	assert.Empty(t, err, "An error occurred while logging in")
	assert.False(t, ok, "Login should not have been accepted")

	_, err = getCookie(recorder, "auth")
	assert.NotEmpty(t, err, "Cookie should not have been set")
}

func TestFunctioningCheckLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObject().HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObject().AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            false,
	})

	assert.Empty(t, err, "Error in login attempt")
	assert.True(t, ok, "Error accepting login")

	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	assert.Empty(t, err, "Error checking login")
	assert.True(t, valid, "Incorrectly reported login as invalid")
	assert.Equal(t, id, userID, "Wrong user ID returned")
}

func TestPreCheckLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	assert.Empty(t, err, "Error checking login")
	assert.False(t, valid, "Incorrectly reported login as valid")
	assert.Empty(t, userID, "An empty user ID should have been returned")

	_, err = getCookie(recorder, "auth")
	assert.NotEmpty(t, err, "auth cookie found, when it shouldn't exist")
}

func TestManipulatedCookieInCheckLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	http.SetCookie(recorder, &http.Cookie{Name: "auth", Value: randStr(64)})

	_, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	if valid {
		t.Error("Should have reported login as invalid")
	} else if err == nil {
		t.Error("Should have raised an error")
	}
}

func TestLogout(t *testing.T) {
	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObject().HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObject().AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            true,
	})

	if !ok || err != nil {
		t.Error("Error in login attempt")
	}

	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	assert.NotEmpty(t, userID, "User ID shouldn't be empty")

	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	recorder = httptest.NewRecorder()

	testObject().Logout(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: request,
	})

	userID, valid, err = testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})
	assert.Empty(t, userID, "User ID should be empty")
	assert.False(t, valid, "Should have reported login as invalid")
}

func TestRmbMeWorkflow(t *testing.T) {
	// Attempt login
	config := Config{
		RedisConn:      "localhost:6379",
		RedisNamespace: randStr(32),
		KMSPath:        testKMSConfigPath,
		DBPath:         testDBPath,
		IdleTimeout:    time.Microsecond,
		ForcedTimeout:  time.Minute * 3,
		RmbMeTimeout:   time.Minute * 5,
		HashIterations: 7,
		HashMemory:     48,
	}
	testObj := New(config)

	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObj.HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObj.AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            true,
	})

	assert.True(t, ok, "Login was not accepted")
	assert.Empty(t, err, "An error occurred while logging in")
	_, err = getCookie(recorder, "auth")
	assert.Empty(t, err, "Cookie was not set")

	// Try to check login again. By now, the login would have expired.
	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})
	assert.Empty(t, err, "Error checking login")
	assert.True(t, valid, "Incorrectly reported login as invalid")
	assert.Equal(t, id, userID, "Wrong user ID returned")
}

func TestLogoutFromAll(t *testing.T) {
	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObject().HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObject().AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            true,
	})

	if !ok || err != nil {
		t.Error("Error in login attempt")
	}

	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	assert.NotEmpty(t, userID, "User ID shouldn't be empty")

	request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
	recorder = httptest.NewRecorder()

	testObject().LogoutAll(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: request,
	})

	userID, valid, err = testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})
	assert.Empty(t, userID, "User ID should be empty")
	assert.False(t, valid, "Should have reported login as invalid")
}

func TestExpiredRmbMeWorkflow(t *testing.T) {
	// Attempt login
	config := Config{
		RedisConn:      "localhost:6379",
		RedisNamespace: randStr(32),
		KMSPath:        testKMSConfigPath,
		DBPath:         testDBPath,
		IdleTimeout:    time.Microsecond,
		ForcedTimeout:  time.Microsecond,
		RmbMeTimeout:   time.Microsecond,
		HashIterations: 7,
		HashMemory:     48,
	}
	testObj := New(config)

	recorder := httptest.NewRecorder()
	id := randStr(64)
	pw := randStr(64)
	hashedPw := testObj.HashPassword(HashPasswordOpts{Password: pw})

	ok, err := testObj.AttemptLogin(AttemptLoginOpts{
		HTTPWriter:       recorder,
		ID:               id,
		ProvidedPassword: pw,
		PasswordHash:     hashedPw,
		RmbMe:            true,
	})

	assert.True(t, ok, "Login was not accepted")
	assert.Empty(t, err, "An error occurred while logging in")
	_, err = getCookie(recorder, "auth")
	assert.Empty(t, err, "Cookie was not set")

	// Try to check login again. By now, the login would have expired.
	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})
	assert.Empty(t, err, "Error checking login")
	assert.Empty(t, userID, "User ID should be empty")
	assert.False(t, valid, "Incorrectly reported login as valid")
}
