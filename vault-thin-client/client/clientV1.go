package client

import (
	"bytes"
	"fmt"
	"github.com/rainer37/go-fun/vault-thin-client/client/secret"
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

	token, err := vaultHttpDoWithParse("POST", completeAuthPath, info.ToPayload(), "", []string{"auth", "client_token"})
	if err != nil {
		log.Error(err)
		return "", nil
	}

	if err := client.SetToken(token); err != nil {
		log.Error(err)
		return "", nil
	}
	return token, nil
}

func (client *VaultClientV1) RetrieveSecret(engine secret.Engine, dataKey string, optionKey string) (string, error) {
	dataPath, err := engine.GetDataPath(dataKey)
	if err != nil {
		log.Error(err)
		return "", fmt.Errorf("while getting data path on secret on %s, got %s", dataKey, err)
	}

	completeSecretPath := fmt.Sprintf("http://%s/%s", client.server.Addr, dataPath)
	// log.Info(completeSecretPath)
	sec, err := vaultHttpDoWithParse(engine.GetVerb(), completeSecretPath, "", client.GetCachedToken(), engine.GetPathToValue(optionKey))
	if err != nil {
		return "", fmt.Errorf("while getting secret on %s, got %s", dataKey, err)
	}

	return sec, nil
}

func (client *VaultClientV1) Crypto(cryptoEngine secret.Engine, dataKey string, sourceText string) (string, error) {
	dataPath, err := cryptoEngine.GetDataPath(dataKey)
	if err != nil {
		log.Error(err)
		return "", fmt.Errorf("while getting data path on crypto on %s, got %s", dataKey, err)
	}

	completeCryptoPath := fmt.Sprintf("http://%s/%s", client.server.Addr, dataPath)
	// log.Info(completeSecretPath)
	sec, err := vaultHttpDoWithParse(cryptoEngine.GetVerb(), completeCryptoPath, sourceText, client.GetCachedToken(), cryptoEngine.GetPathToValue(""))
	if err != nil {
		return "", fmt.Errorf("while getting crypto on %s, got %s", dataKey, err)
	}

	return sec, nil
}

func (client *VaultClientV1) WrapIt(action, toWrap, optionKey, ttl string) (string, error) {
	wrapURL := fmt.Sprintf("http://%s/v1/sys/wrapping/%s", client.server.Addr, action)
	req, err := http.NewRequest("POST", wrapURL, bytes.NewBuffer([]byte(toWrap)))

	if err != nil {
		log.Error(err)
		return "", err
	}

	req.Header.Set(vaultTokenHeaderKey, client.cachedToken)
	req.Header.Set(vaultWrappingTTL, ttl)

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error(err)
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("response from Vault, but not 200: %s", string(body))
	}
	var keys []string
	switch action {
	case "wrap":
		keys = []string{"wrap_info", "token"}
	case "rewrap":
		keys = []string{"wrap_info", "token"}
	case "unwrap":
		keys = []string{"data", optionKey}
	}
	return jsonDrip(keys, body)
}