package auth

import (
	"context"
	"fmt"
	"github.com/RushOwl/quickbooks-go/util/envvar"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestConfig_Connect(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name        string
		args        args
		wantAuthUri string
		wantErr     error
	}{
		{args: args{req: &http.Request{}}},
	}
	c := GetAuthConfig()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.args.req.Context()
			ctx = context.WithValue(ctx, "gorilla.csrf.Token", "12312321")
			tt.args.req = tt.args.req.WithContext(ctx)
			gotAuthUri, _, gotErr := c.Connect(tt.args.req)
			t.Log(gotAuthUri)
			if gotErr != nil {
				t.Errorf("Connect() = %v, want %v", gotErr, tt.wantErr)
			}
			if gotAuthUri != tt.wantAuthUri {
				t.Errorf("Connect() = %v, want %v", gotAuthUri, tt.wantAuthUri)
			}
		})
	}
	csrfToken, _ := envvar.GetEnvVar(envvar.CsrfToken)
	CSRF := csrf.Protect([]byte(csrfToken))
	r := mux.NewRouter()
	r.HandleFunc("/oauth/login", oauthLoginHandler)
	r.HandleFunc("/oauth/callback", oauthCallbackHandler)
	_ = http.ListenAndServe(":51010", CSRF(r))
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	for key, values := range r.Header {
		for _, v := range values {
			fmt.Printf("%s: %s", key, v)
		}
	}
	fmt.Printf("got / request\n")
	_, _ = io.WriteString(w, "This is my website!\n")
}

func oauthLoginHandler(w http.ResponseWriter, r *http.Request) {
	c := GetAuthConfig()
	authUri, encryptedCsrfToken, _ := c.Connect(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "intuit_open_id_csrf",
		Value:    encryptedCsrfToken,
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		HttpOnly: false,
		SameSite: 1,
	})
	_, _ = io.WriteString(w, authUri)
}
