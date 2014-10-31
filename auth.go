package tauth

import (
	"errors"
	"fmt"
	"github.com/gorilla/context"
	"net/http"
)

type TokenAuth struct {
	handler             http.Handler
	store               TokenStore
	getter              TokenGetter
	UnauthorizedHandler http.HandlerFunc
}

type TokenGetter interface {
	GetTokenFromRequest(req *http.Request) string
}

type TokenStore interface {
	CheckToken(token string) (Token, error)
}

type Token interface {
	IsExpired() bool
	fmt.Stringer
	ClaimGetter
}

type ClaimSetter interface {
	SetClaim(string, interface{}) ClaimSetter
}

type ClaimGetter interface {
	Claims(string) interface{}
}

func DefaultUnauthorizedHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(401)
	fmt.Fprint(w, "unauthorized")
}

type QueryStringTokenGetter struct {
	Parameter string
}

func (q QueryStringTokenGetter) GetTokenFromRequest(req *http.Request) string {
	return req.URL.Query().Get(q.Parameter)
}

func NewQueryStringTokenGetter(parameter string) *QueryStringTokenGetter {
	return &QueryStringTokenGetter{
		Parameter: parameter,
	}
}

/*
	Returns a TokenAuth object implemting Handler interface

	if a handler is given it proxies the request to the handler

	if a unauthorizedHandler is provided, unauthorized requests will be handled by this HandlerFunc,
	otherwise a default unauthorized handler is used.

	store is the TokenStore that stores and verify the tokens
*/
func NewTokenAuth(handler http.Handler, unauthorizedHandler http.HandlerFunc, store TokenStore, getter TokenGetter) *TokenAuth {
	t := &TokenAuth{
		handler:             handler,
		store:               store,
		getter:              getter,
		UnauthorizedHandler: unauthorizedHandler,
	}
	if t.getter == nil {
		t.getter = NewQueryStringTokenGetter("token")
	}
	if t.UnauthorizedHandler == nil {
		t.UnauthorizedHandler = DefaultUnauthorizedHandler
	}
	return t
}

/* wrap a HandlerFunc to be authenticated */
func (t *TokenAuth) HandleFunc(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		token, err := t.Authenticate(req)
		if err != nil {
			t.UnauthorizedHandler.ServeHTTP(w, req)
			return
		}
		context.Set(req, "token", token)
		handlerFunc.ServeHTTP(w, req)
	}
}

func (t *TokenAuth) Authenticate(req *http.Request) (Token, error) {
	strToken := t.getter.GetTokenFromRequest(req)
	if strToken == "" {
		return nil, errors.New("token required")
	}
	token, err := t.store.CheckToken(strToken)
	if err != nil {
		return nil, errors.New("Invalid token")
	}
	return token, nil
}

/* implement Handler */
func (t *TokenAuth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, err := t.Authenticate(req)
	if err != nil {
		t.UnauthorizedHandler.ServeHTTP(w, req)
		return
	}
	context.Set(req, "token", token)
	t.handler.ServeHTTP(w, req)
	context.Clear(req)
}

func Get(req *http.Request) Token {
	return context.Get(req, "token").(Token)
}
