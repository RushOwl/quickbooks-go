package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

/*
 * Call JWKS endpoint and retrieve the key values
 */
func (c *Config) CallJWKSAPI() (*JWKSResponse, error) {
	log.Println("Entering CallJWKSAPI ")
	client := &http.Client{}
	request, err := http.NewRequest("GET", c.OpenIdConfiguration.JwksUri, nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Exiting CallJWKSAPI ")
	return getJWKSResponse([]byte(body))
}

type JWKSResponse struct {
	KEYS []Keys `json:"keys"`
}

type Keys struct {
	KTY string `json:"kty"`
	E   string `json:"e"`
	USE string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
}

func getJWKSResponse(body []byte) (*JWKSResponse, error) {
	var s = new(JWKSResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error getting JWKSResponse:", err)
	}
	return s, err
}
