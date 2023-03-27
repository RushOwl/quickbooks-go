package auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/RushOwl/quickbooks-go/util/envvar"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

/*
// Generate ES512 key
openopenssl ecparam -genkey -name secp521r1 -noout -out ecdsa-p521-private.pem
openssl ec -in ecdsa-p521-private.pem -pubout -out ecdsa-p521-public.pem
*/

func GenerateEncodedState(req *http.Request, privateKeyStr string) (csrfToken, encryptedCsrfToken string, err error) {
	csrfToken = csrf.Token(req)
	tokenExpMinStr, isExist := envvar.GetEnvVar(envvar.EcryptedCsrfExpiryMinute)
	if !isExist {
		log.Error(err)
		return
	}
	var tokenExpMin int64 = 10
	tokenExpMin, err = strconv.ParseInt(tokenExpMinStr, 10, 64)
	if err != nil {
		log.Error(err)
		return
	}
	tokenData := jwt.MapClaims{
		"state": csrfToken,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Minute * time.Duration(tokenExpMin)).Unix(),
	}
	encryptedCsrfToken, err = GenerateToken(jwt.SigningMethodES512, privateKeyStr, tokenData)
	if err != nil {
		log.Error(err)
		return
	}
	return
}

func GenerateToken(methodEncrypt *jwt.SigningMethodECDSA, privateKeyStr string, tokenData jwt.MapClaims) (token string, err error) {
	tokenGen := jwt.NewWithClaims(methodEncrypt, tokenData)
	if privateKeyStr == "" {
		err = fmt.Errorf("empty private key")
		return
	}
	privateKey, err := decodePrivateECDSA(privateKeyStr)
	if err != nil || privateKey == nil {
		return
	}

	token, err = tokenGen.SignedString(privateKey)
	if err != nil {
		return
	}
	return
}

func decodePublicECDSA(pemEncodedPub string) (pubKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub == nil {
		return nil, errors.New("invalid pubkey")
	}
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	pubKey = genericPublicKey.(*ecdsa.PublicKey)
	return pubKey, nil
}

func decodePrivateECDSA(pemEncoded string) (privateKey *ecdsa.PrivateKey, err error) {
	block, rest := pem.Decode([]byte(pemEncoded))
	if len(rest) != 0 && block == nil {
		err = fmt.Errorf("invalid private_key format")
		log.Error(err)
		return
	}
	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		log.Error(err)
		return
	}
	return
}

func ValidateToken(publicKeyStr string, token string) (valid bool, claims jwt.MapClaims, err error) {
	if token == "" {
		return false, claims, fmt.Errorf("empty token")
	}
	tkn, err := jwt.Parse(token, func(tkn *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodES512 != tkn.Method {
			err = errors.New("invalid signing method")
			return nil, err
		}
		var pubKey *ecdsa.PublicKey
		pubKey, err = decodePublicECDSA(publicKeyStr)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	})
	if err != nil {
		log.Error(err)
		return false, nil, err
	}
	var ok bool
	if claims, ok = tkn.Claims.(jwt.MapClaims); ok && tkn.Valid {
		var exp int64
		switch e := claims["exp"].(type) {
		case string:
			var conv int
			conv, err = strconv.Atoi(e)
			if err != nil {
				log.Error(err)
				break
			}
			exp = int64(conv)
		case float64:
			exp = int64(e)
		}
		if exp < time.Now().Unix() {
			return false, claims, fmt.Errorf("expired token")
		}
		return true, claims, nil
	}
	return false, claims, fmt.Errorf("invalid token")
}
