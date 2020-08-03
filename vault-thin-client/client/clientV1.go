package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"regexp"
)

var tokenPattern = regexp.MustCompile(`^s\..*`)

type VaultClientV1 struct {
	server ServerInfo
	cachedToken string
}

func New(serverAddr, cachedToken string) *VaultClientV1 {
	return &VaultClientV1{
		server:      ServerInfo{serverAddr},
		cachedToken: cachedToken,
	}
}

func doesNotLookLikeAVaultToken(token string) bool {
	return !tokenPattern.Match([]byte(token))
}

func (client *VaultClientV1) SetToken(newToken string) error {
	if doesNotLookLikeAVaultToken(newToken) {
		log.Infof("bad token: %s", newToken)
		return fmt.Errorf("does not look like a Vault token: %s", newToken)
	}
	client.cachedToken = newToken
	return nil
}

func (client *VaultClientV1) GetCachedToken() string {
	return client.cachedToken
}

func (client *VaultClientV1) Login(method string, args []string, path string, info AuthInfo) (string, error) {

	pathTemplate, ok := authMethodPathMap[method]
	if !ok {
		pathTemplate = authMethodPathMap["general"]
	}

	completeAuthPath := fmt.Sprintf("http://%s/"  + pathTemplate, client.server.Addr, path, args[0])
	req, err := http.NewRequest("POST", completeAuthPath, bytes.NewBuffer([]byte(info.ToPayload())))

	if err != nil {
		log.Error(err)
		return "", err
	}

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer resp.Body.Close()

	var data map[string]interface{}

	body, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Error(err)
		return "", nil
	}

	authSection, ok := data["auth"]
	if !ok {
		return "", fmt.Errorf("response has no auth section returned")
	}

	token, ok := authSection.(map[string]interface{})["client_token"] // Fix me
	if !ok {
		return "", fmt.Errorf("response has no token section returned")
	}

	if err := client.SetToken(token.(string)); err != nil {
		log.Error(err)
		return "", nil
	}

	return token.(string), nil
}