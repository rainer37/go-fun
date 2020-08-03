package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type AuthInfo interface {
	ToPayload() string
}

const authMethodBase = "v1/auth/%s/"
const vaultTokenHeaderKey = "X-Vault-Token"

var authMethodPathMap = map[string]string {
	"userpass": authMethodBase + "login/%s",
	"okta": authMethodBase + "login/%s",
	"default": authMethodBase + "login",
}

type VaultClient interface {
	GetCachedToken() string
	SetToken(token string) error
	Login(method string, args []string, path string, info AuthInfo) (string, error)
	RetrieveSecret(engine string) (string, error)
}

type ServerInfo struct {
	Addr string
}

func vaultHttpDo(verb, path, payload, token string) ([]byte, error) {
	req, err := http.NewRequest(verb, path, bytes.NewBuffer([]byte(payload)))

	if err != nil {
		log.Error(err)
		return nil, err
	}

	req.Header.Set(vaultTokenHeaderKey, token)

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return body, nil
}

func vaultHttpDoWithParse(verb, path, payload, token string, keys []string) (string, error) {
	result, err := vaultHttpDo(verb, path, payload, token)
	if err != nil {
		log.Error(err)
		return string(result), err
	}

	var data map[string]interface{}
	var value string
	err = json.Unmarshal(result, &data)
	if err != nil {
		log.Error(err)
		return string(result), err
	}

	for _, key := range keys {
		val, ok := data[key]
		if !ok {
			return "", fmt.Errorf("bad key path %s at %s", keys, key)
		}
		if _, ok := val.(string); ok {
			value = val.(string)
			break
		}
		data = val.(map[string]interface{})
	}

	return value, nil
}