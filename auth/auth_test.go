package auth

import (
	"fmt"
	"github.com/RushOwl/quickbooks-go/util/envvar"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestConfig_Connect(t *testing.T) {
	type args struct {
		req *http.Request
	}
	//tests := []struct {
	//	name        string
	//	args        args
	//	wantAuthUri string
	//	wantErr     error
	//}{
	//	{args: args{req: &http.Request{}}},
	//}
	//c := GetAuthConfig()
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		ctx := tt.args.req.Context()
	//		ctx = context.WithValue(ctx, "gorilla.csrf.Token", "12312321")
	//		tt.args.req = tt.args.req.WithContext(ctx)
	//		gotAuthUri, _, gotErr := c.Connect(tt.args.req)
	//		t.Log(gotAuthUri)
	//		if gotErr != nil {
	//			t.Errorf("Connect() = %v, want %v", gotErr, tt.wantErr)
	//		}
	//		if gotAuthUri != tt.wantAuthUri {
	//			t.Errorf("Connect() = %v, want %v", gotAuthUri, tt.wantAuthUri)
	//		}
	//	})
	//}
	csrfToken, _ := envvar.GetEnvVar(envvar.CsrfToken)
	CSRF := csrf.Protect([]byte(csrfToken))
	r := mux.NewRouter()
	r.HandleFunc("/oauth/login", oauthLoginHandler)
	r.HandleFunc("/oauth/callback", oauthCallbackHandler)
	_ = http.ListenAndServe(":51010", CSRF(r))
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	c := GetAuthConfig()
	realmId, accessToken, refreshToken, intuitJwToken, err := c.VerifyOauth2Callback(r)
	fmt.Println(realmId, accessToken, refreshToken, intuitJwToken, err)
	for key, values := range r.Header {
		for _, v := range values {
			fmt.Printf("%s: %s", key, v)
		}
	}
	for _, cookie := range r.Cookies() {
		fmt.Printf("%s: %s", cookie.Name, cookie.Value)
	}
	fmt.Printf("got / request\n")
	_, _ = io.WriteString(w, "This is my website!\n")
}

func oauthLoginHandler(w http.ResponseWriter, r *http.Request) {
	c := GetAuthConfig()
	authUri, encryptedCsrfToken, _ := c.Connect(r)
	cookieName, _ := envvar.GetEnvVar(envvar.EcryptedCsrfCookieName)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    encryptedCsrfToken,
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		HttpOnly: false,
		SameSite: 1,
	})
	http.Redirect(w, r, authUri, 302)
}

func TestConfig_UpdateOpenIdEndpoints(t *testing.T) {
	type fields struct {
		mu                          sync.Mutex
		ClientId                    string
		ClientSecret                string
		RedirectUri                 string
		OpenIdConfigurationEndpoint string
		OpenIdConfiguration         OpenIdConfiguration
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				mu:                          tt.fields.mu,
				ClientId:                    tt.fields.ClientId,
				ClientSecret:                tt.fields.ClientSecret,
				RedirectUri:                 tt.fields.RedirectUri,
				OpenIdConfigurationEndpoint: tt.fields.OpenIdConfigurationEndpoint,
				OpenIdConfiguration:         tt.fields.OpenIdConfiguration,
			}
			if err := c.UpdateOpenIdEndpoints(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateOpenIdEndpoints() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_UpdateOpenIdEndpoints1(t *testing.T) {
	type fields struct {
		mu                          sync.Mutex
		ClientId                    string
		ClientSecret                string
		RedirectUri                 string
		OpenIdConfigurationEndpoint string
		OpenIdConfiguration         OpenIdConfiguration
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{fields: fields{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				mu:                          tt.fields.mu,
				ClientId:                    tt.fields.ClientId,
				ClientSecret:                tt.fields.ClientSecret,
				RedirectUri:                 tt.fields.RedirectUri,
				OpenIdConfigurationEndpoint: tt.fields.OpenIdConfigurationEndpoint,
				OpenIdConfiguration:         tt.fields.OpenIdConfiguration,
			}
			if err := c.UpdateOpenIdEndpoints(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateOpenIdEndpoints() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
