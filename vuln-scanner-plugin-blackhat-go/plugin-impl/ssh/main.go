package main

import (
	"bytes"
	"fmt"
	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var commonUsername = []string {
	"root",
	"admin",
	"ec2-user",
	"ubuntu",
	"sshuser",
}

var weakPass  = []string {
	"123456",
	"admin",
	"111111",
	"password",
}

type SSHChecker struct {}

func makeConfig(username, pass string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func scan(host string, port uint64, config *ssh.ClientConfig) error {
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		log.Debug("Failed to dial: ", err)
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		log.Debug("Failed to create session: ", err)
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Debug("Failed to run: " + err.Error())
		return err
	}
	log.Info(b.String())
	return nil
}

func (sc *SSHChecker) Check(host string, port uint64) *scanner.Result {
	res := new(scanner.Result)

	for _, user := range commonUsername {
		for _, pass := range weakPass {
			log.Debug("trying ssh with %s + %s on %s:%d", user, pass, host, port)
			config := makeConfig(user, pass)
			err := scan(host, port, config)
			if err != nil {
				res.Vulnerable = true
				res.Details = fmt.Sprintf("ssh %s@%s -p %d # password=%s", user, host, port, pass)
			}
		}
	}

	return res
}

func New() scanner.Checker {
	return new(SSHChecker)
}