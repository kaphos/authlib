package authlib

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
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

	if !ok {
		t.Error("Login was not accepted")
	}
	if err != nil {
		t.Error("An error occurred while logging in:", err)
	}

	_, err = getCookie(recorder, "auth")
	if err != nil {
		t.Error("Cookie was not set")
	}
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

	if err != nil {
		t.Error("An error occurred while logging in:", err)
	}
	if ok {
		t.Error("Login should not have been accepted")
	}

	_, err = getCookie(recorder, "auth")
	if err == nil {
		t.Error("Cookie should not have been set")
	}
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

	if !ok || err != nil {
		t.Error("Error in login attempt")
	}

	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	if err != nil {
		t.Error("Error checking login:", err)
	} else if !valid {
		t.Error("Incorrectly reported login as invalid")
	} else if userID != id {
		t.Error("Wrong user ID returned")
	}
}

func TestPreCheckLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	userID, valid, err := testObject().CheckLogin(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	if err != nil {
		t.Error("Error checking login:", err)
	} else if valid {
		t.Error("Incorrectly reported login as valid")
	} else if userID != "" {
		t.Error("An empty user ID should have been returned")
	}

	_, err = getCookie(recorder, "auth")
	if err == nil {
		t.Error("auth cookie found, when it shouldn't exist")
	}
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

	testObject().Logout(HTTPOpts{
		HTTPWriter:  recorder,
		HTTPRequest: &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}},
	})

	if _, err := getCookie(recorder, "auth"); err != nil {
		t.Error("Logout did not remove auth cookie")
	}

	if _, err := getCookie(recorder, "rmbme"); err != nil {
		t.Error("Logout did not remove rmbme cookie")
	}
}
