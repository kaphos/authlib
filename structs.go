package authlib

import (
	"net/http"
	"time"

	"github.com/opentracing/opentracing-go"
)

type comparePasswordOpts struct {
	password    string
	encodedHash string
	spanContext opentracing.SpanContext
}

// cookieOpts is the structure of the cookie that is used
// to authenticate users after they have logged in.
type cookieOpts struct {
	key         string
	token       string
	spanContext opentracing.SpanContext
}

type storeValue struct {
	HashedToken string
	UserID      string
	Expires     time.Time
	MaxExpiry   time.Time
}

// HashPasswordOpts bundles the options for hashing a password.
type HashPasswordOpts struct {
	Password    string
	SpanContext opentracing.SpanContext // Used for instrumenting with opentracing API
}

// AttemptLoginOpts bundles the options for logging a user in.
// It contains the login details that is being passed in to be checked & stored.
type AttemptLoginOpts struct {
	HTTPWriter       http.ResponseWriter
	ID               string // Unique identifier of the user
	ProvidedPassword string
	PasswordHash     string
	RmbMe            bool
	SpanContext      opentracing.SpanContext // Used for instrumenting with opentracing API
}

// HTTPOpts contains the http.ResponseWriter and http.Request objects,
// to read & write cookies as needed.
type HTTPOpts struct {
	HTTPWriter  http.ResponseWriter
	HTTPRequest *http.Request
	SpanContext opentracing.SpanContext // Used for instrumenting with opentracing API
}

type saveLoginOpts struct {
	userID      string
	rmbMe       bool
	w           http.ResponseWriter
	spanContext opentracing.SpanContext
}
