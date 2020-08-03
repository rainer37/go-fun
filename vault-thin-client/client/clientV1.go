package client

import (
	"fmt"
	log "github.com/sirupsen/logrus"
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

	return token, nil
}