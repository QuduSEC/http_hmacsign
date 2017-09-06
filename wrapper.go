package http_hmacsign

import (
	"net/http"
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"errors"
)

func SignRequest (r *http.Request, keyID string, keySecret string, hlist map[string]string) error {

	//Check URI
	uri := r.URL.EscapedPath()

	if uri == "" {
		uri = "/"
	}

	// Prepare the signature to include hlist headers:
	signatureString := strings.ToLower("(request-target): ") + r.Method + uri

	//Check Headers
	for k, v := range hlist {
		if r.Header.Get(k) != "" {
			signatureString += "\n"
			signatureString += strings.ToLower(k+": ") + v
		} else {
			return errors.New("Not all transmitted headers for creating a signature exist")
		}
	}

	//Create Signature
	key := []byte(keySecret)
	hmac := hmac.New(sha1.New,key)
	_, err := hmac.Write([]byte(signatureString))
	if err != nil {
		return err
	}

	// Base64 and URL Encode the string
	hashString := base64.StdEncoding.EncodeToString(hmac.Sum(nil))
	signature := url.QueryEscape(hashString)

	r.Header.Add("Authorization", "Signature keyId=\""+keyID+"\",algorithm=\"hmac-sha1\",headers=\"(request-target) date\",signature=\"" + signature + "\"")

	return nil
}



