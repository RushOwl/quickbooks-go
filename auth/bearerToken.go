package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

/*
 * Method to retrive access token (bearer token)
 */
func (c *Config) RetrieveBearerToken(code string) (*BearerTokenResponse, error) {
	log.Println("Entering RetrieveBearerToken ")
	client := &http.Client{}
	data := url.Values{}
	//set parameters
	data.Set("grant_type", "authorization_code")
	data.Add("code", code)
	data.Add("redirect_uri", c.RedirectUri)

	tokenEndpoint := c.OpenIdConfiguration.TokenEndpoint
	request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	//set headers
	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.Header.Set("Authorization", "Basic "+c.BasicAuth())

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	bearerTokenResponse, err := getBearerTokenResponse([]byte(body))
	log.Println("Exiting RetrieveBearerToken ")
	return bearerTokenResponse, err
}

type BearerTokenResponse struct {
	RefreshToken           string `json:"refresh_token"`
	AccessToken            string `json:"access_token"`
	TokenType              string `json:"token_type"`
	IdToken                string `json:"id_token"`
	ExpiresIn              int64  `json:"expires_in"`
	XRefreshTokenExpiresIn int64  `json:"x_refresh_token_expires_in"`
}

func getBearerTokenResponse(body []byte) (*BearerTokenResponse, error) {
	var s = new(BearerTokenResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error getting BearerTokenResponse:", err)
	}
	return s, err
}
