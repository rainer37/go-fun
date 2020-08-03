package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rainer37/go-fun/vault-thin-client/client/secret"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
)

type AuthInfo interface {
	ToPayload() string
}

const authMethodBase = "v1/auth/%s/"
const vaultTokenHeaderKey = "X-Vault-Token"
const vaultWrappingTTL = "X-Vault-Wrap-TTL"

var authMethodPathMap = map[string]string {
	"userpass": authMethodBase + "login/%s",
	"okta": authMethodBase + "login/%s",
	"default": authMethodBase + "login",
}

type VaultClient interface {
	GetCachedToken() string
	SetToken(token string) error
	Login(method string, args []string, path string, info AuthInfo) (string, error)
	RetrieveSecret(engine secret.Engine, dataKey string, optionKey string) (string, error)
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response from Vault, but not 200: %s", string(body))
	}
	return body, nil
}

func vaultHttpDoWithParse(verb, path, payload, token string, keys []string) (string, error) {
	result, err := vaultHttpDo(verb, path, payload, token)
	if err != nil {
		log.Error(err)
		return string(result), err
	}
	return jsonDrip(keys, result)
}

func jsonDrip(keys []string, result []byte) (string, error) {
	var data map[string]interface{}
	err := json.Unmarshal(result, &data)
	if err != nil {
		log.Error(err)
		return string(result), err
	}
	lastKey := keys[len(keys)-1]
	keys = keys[:len(keys)-1]

	for _, key := range keys {
		//log.Infof("%v %s", data, token)
		val, ok := data[key]
		if !ok {
			return "", fmt.Errorf("bad key path %s at %s", keys, key)
		}
		data = val.(map[string]interface{})
	}

	if !strings.Contains(lastKey, ":") {
		vbool, ok := data[lastKey].(bool)
		if ok {
			if vbool {
				return "true", nil
			}
			return "false", nil
		}

		v, ok := data[lastKey].(string)
		if !ok {
			return "", fmt.Errorf("bad last key path %s at %s", keys, lastKey)
		}
		return v, nil
	}

	// parse last possible composite key
	multiKeys := strings.Split(lastKey, ":")

	value := "{"
	for _, k := range multiKeys {
		v, ok := data[k]
		if !ok {
			return "", fmt.Errorf("bad last multi key path %s at %s from %s", keys, k, multiKeys)
		}
		value += fmt.Sprintf("\"%s\":\"%s\",", k, v)
	}
	value = value[:len(value)-1] + "}"
	return value, nil
}