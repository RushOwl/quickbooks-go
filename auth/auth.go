package auth

import (
	"encoding/json"
	"errors"
	v0 "github.com/RushOwl/quickbooks-go/auth/v0"
	"github.com/RushOwl/quickbooks-go/util/envvar"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	mu sync.Mutex
	// Loads once
	ClientId                    string
	ClientSecret                string
	RedirectUri                 string
	OpenIdConfigurationEndpoint string

	// Loads daily
	OpenIdConfiguration OpenIdConfiguration
}

type OpenIdConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

var authConf = Config{}

func GetAuthConfig() Config {
	authConf.mu.Lock()
	defer authConf.mu.Unlock()
	var exist bool
	if authConf.ClientId == "" {
		authConf.ClientId, exist = envvar.GetEnvVar(envvar.IntuitClientId)
		if !exist {
			log.Errorf("missing env var %s", envvar.IntuitClientId)
		}
	}
	if authConf.ClientSecret == "" {
		authConf.ClientSecret, exist = envvar.GetEnvVar(envvar.IntuitClientSecret)
		if !exist {
			log.Errorf("missing env var %s", envvar.IntuitClientSecret)
		}
	}
	if authConf.RedirectUri == "" {
		authConf.RedirectUri, exist = envvar.GetEnvVar(envvar.IntuitRedirectUri)
		if !exist {
			log.Errorf("missing env var %s", envvar.IntuitRedirectUri)
		}
	}
	if authConf.OpenIdConfigurationEndpoint == "" {
		authConf.OpenIdConfigurationEndpoint, exist = envvar.GetEnvVar(envvar.IntuitOpenIdConfigurationEndpoint)
		if !exist {
			log.Errorf("missing env var %s", envvar.IntuitOpenIdConfigurationEndpoint)
		}
	}
	_ = authConf.UpdateOpenIdEndpoints()
	return authConf
}

func (c *Config) UpdateOpenIdEndpoints() (err error) {
	client := &http.Client{}
	request, err := http.NewRequest("GET", c.OpenIdConfigurationEndpoint, nil)
	if err != nil {
		log.Error(err)
		return
	}
	request.Header.Set("accept", "application/json")

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return
	}
	latestOpenIdEndpointsResponse := &OpenIdConfiguration{}
	err = json.Unmarshal(body, &latestOpenIdEndpointsResponse)
	if err != nil {
		log.Error(err)
		return
	}
	c.OpenIdConfiguration = *latestOpenIdEndpointsResponse
	return
}

func (c *Config) getOAuthClient() (client *oauth2.Config) {
	client = &oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   c.OpenIdConfiguration.AuthorizationEndpoint,
			TokenURL:  c.OpenIdConfiguration.TokenEndpoint,
			AuthStyle: 0,
		},
		RedirectURL: c.RedirectUri,
		Scopes: []string{
			"com.intuit.quickbooks.accounting",
			"openid",
			"profile",
			"email",
			"phone",
			"address",
		},
	}
	return
}

func (c *Config) Connect(req *http.Request) (authUri string, encryptedCsrfToken string, err error) {
	privateKeyStr, isExist := envvar.GetEnvVar(envvar.EcryptedCsrfPrivateKey)
	if !isExist {
		return
	}
	csrfToken, encryptedCsrfToken, err := v0.GenerateEncodedState(req, privateKeyStr)
	if err != nil {
		log.Error(err)
		return
	}
	if csrfToken == "" {
		err = errors.New("CSRF is not enabled")
		log.Error(err)
		return
	}
	authUri = c.getOAuthClient().AuthCodeURL(csrfToken)
	return
}

func (c *Config) VerifyOauth2Callback(req *http.Request) (realmId string, accessToken string, refreshToken string, intuitJWToken string, err error) {
	state := req.URL.Query().Get("state")
	code := req.URL.Query().Get("code")
	realmId = req.URL.Query().Get("realmId")

	cookieName, isExist := envvar.GetEnvVar(envvar.EcryptedCsrfCookieName)
	if !isExist {
		err = errors.New("missing CSRF cookie name")
		log.Error(err)
		return
	}
	encryptedCsrfCookie, err := req.Cookie(cookieName)
	if err != nil {
		log.Error(err)
		return
	}

	encryptedCsrfPublicKey, isExist := envvar.GetEnvVar(envvar.EcryptedCsrfPublicKey)
	if !isExist {
		err = errors.New("missing CSRF cookie name")
		log.Error(err)
		return
	}
	isValid, claims, err := v0.ValidateToken(encryptedCsrfPublicKey, encryptedCsrfCookie.Value)
	if err != nil {
		log.Error(err)
		return
	}
	if !isValid {
		log.Error("token is not valid")
		return
	}

	if sessionState, isSessionExist := claims["state"]; !(isSessionExist && sessionState == state) {
		log.Error("invalid state")
		return
	}

	bearerTokenResponse, err := v0.RetrieveBearerToken(code)
	idToken := bearerTokenResponse.IdToken
	if !v0.ValidateIDToken(idToken) {
		log.Error("invalid idToken")
		return
	}

	tokenData := jwt.MapClaims{
		"realmId":      realmId,
		"accessToken":  bearerTokenResponse.AccessToken,
		"refreshToken": bearerTokenResponse.RefreshToken,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Minute * time.Duration(1440)).Unix(),
	}

	privateKeyStr, isExist := envvar.GetEnvVar(envvar.EcryptedCsrfPrivateKey)
	if !isExist {
		return
	}

	intuitJWToken, err = v0.GenerateToken(jwt.SigningMethodES512, privateKeyStr, tokenData)
	if err != nil {
		log.Error(err)
		return
	}
	return
}
