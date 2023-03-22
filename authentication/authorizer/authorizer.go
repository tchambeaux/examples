package authorizer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

func VerifyToken(token string, keys []map[string]interface{}) error {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		for _, key := range keys {
			if t.Header["kid"] != key["kid"] {
				continue
			}
			b, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			k, err := jwk.ParseKey(b)
			if err != nil {
				return nil, err
			}
			pem, err := jwk.Pem(k)
			if err != nil {
				return nil, err
			}
			return jwt.ParseRSAPublicKeyFromPEM(pem)
		}
		return nil, nil
	})
	if err != nil {
		return err
	}
	return parsedToken.Claims.Valid()
}

func AppendKeysFromUrl(ctx context.Context, client http.Client, urls []string) ([]map[string]interface{}, error) {
	keys := []map[string]interface{}{}
	for _, endpoint := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		r, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		var res = map[string]interface{}{}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, err
		}
		keyList, ok := res["keys"].([]interface{})
		if !ok {
			return nil, errors.New("keys should be of type slice")
		}
		for _, v := range keyList {
			if k, ok := v.(map[string]interface{}); ok {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}
