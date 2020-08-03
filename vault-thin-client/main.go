package main

import (
	"flag"
	"fmt"
	vaultClient "github.com/rainer37/go-fun/vault-thin-client/client"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
)

var (
	vaultAddr string
	vaultVersionPattern = regexp.MustCompile(`"version":"([0-9.]+)"`)
)

func isVaultRunning() bool {
	res, err := http.Get(fmt.Sprintf("http://%s/v1/sys/seal-status", vaultAddr))
	if err != nil {
		log.Fatal("vault is not running at provided address")
		return false
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("invalid status response from Vault")
		return false
	}
	version := vaultVersionPattern.FindSubmatch(body)
	if len(version) != 2 {
		log.Fatal("cannot parse vault info")
		return false
	}
	log.Infof("Vault version: %s", version[1])
	return true
}

func init() {
	flag.StringVar(&vaultAddr, "vault-addr",  "127.0.0.1:8200", "vault name server address")
	flag.Parse()
}

type Password struct {
	pass string
}

func (pass Password) ToPayload() string {
	return fmt.Sprintf("{\"password\":\"%s\"}", pass.pass)
}

func main() {
	if !isVaultRunning() {
		os.Exit(1)
	}
	log.Infof("Vault is running at %s...", vaultAddr)

	client := vaultClient.New(vaultAddr, "")
	token, err := client.Login("userpass", []string{"ella"}, "up", Password{"rain0908"})
	if err != nil {
		log.Error(err)
	}
	log.Infof(token)
}
