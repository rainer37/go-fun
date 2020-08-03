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

func (client *VaultClientV1) setToken(newToken string) error {
	if doesNotLookLikeAVaultToken(newToken) {
		log.Infof("bad token: %s", newToken)
		return fmt.Errorf("does not look like a Vault token: %s", newToken)
	}
	client.cachedToken = newToken
	return nil
}

func (client *VaultClientV1) getToken() string {
	return client.cachedToken
}
