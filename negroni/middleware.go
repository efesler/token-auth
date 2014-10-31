package negronitauth

import (
	"github.com/freehaha/token-auth"
	"github.com/gorilla/context"
	"net/http"
)

type TokenAuth struct {
	auth *tauth.TokenAuth
}

func NewTokenAuth(unauthorizedHandler http.HandlerFunc, store tauth.TokenStore, getter tauth.TokenGetter) *TokenAuth {
	t := &TokenAuth{
		auth: tauth.NewTokenAuth(nil, unauthorizedHandler, store, getter),
	}
	return t
}

/* as Negroni middleware, implementing negroni.Handler */
func (t *TokenAuth) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	token, err := t.auth.Authenticate(req)
	if err != nil {
		t.auth.UnauthorizedHandler.ServeHTTP(w, req)
		return
	}
	context.Set(req, "token", token)
	next(w, req)
	context.Clear(req)
}

func Get(req *http.Request) *tauth.Token {
	return context.Get(req, "token").(*tauth.Token)
}
