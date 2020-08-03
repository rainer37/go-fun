package client

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("got response from Vault, but not 200")
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
	err = json.Unmarshal(result, &data)
	if err != nil {
		log.Error(err)
		return string(result), err
	}
	lastKey := keys[len(keys)-1]
	keys = keys[:len(keys)-1]

	for _, key := range keys {
		// log.Infof("%v %s", data, token)
		val, ok := data[key]
		if !ok {
			return "", fmt.Errorf("bad key path %s at %s", keys, key)
		}
		data = val.(map[string]interface{})
	}

	if !strings.Contains(lastKey, ":") {
		v, ok := data[lastKey].(string)
		if !ok {
			return "", fmt.Errorf("bad key path %s at %s", keys, lastKey)
		}
		return v, nil
	}

	// parse last possible composite key
	multiKeys := strings.Split(lastKey, ":")

	value := "{"
	for _, k := range multiKeys {
		v, ok := data[k]
		if !ok {
			return "", fmt.Errorf("bad key path %s at %s", keys, k)
		}
		value += fmt.Sprintf("\"%s\":\"%s\",", k, v)
	}
	value = value[:len(value)-1] + "}"
	return value, nil
}