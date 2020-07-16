package main

import (
	"bytes"
	"fmt"
	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"sync"
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

func scan(host string, port uint64, username, pass string) error {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

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

type Cred struct {
	user string
	pass string
}

func credentialGen() <-chan Cred {
	creds := make(chan Cred)
	go func() {
		for _, user := range commonUsername {
			for _, pass := range weakPass {
				creds <- Cred{user, pass}
			}
		}
		close(creds)
	}()
	return creds
}

func (sc *SSHChecker) Check(host string, port uint64) *scanner.Result {
	//log.SetLevel(log.DebugLevel)
	res := new(scanner.Result)

	var wg sync.WaitGroup
	creds := credentialGen()

	for u := range creds {
		wg.Add(1)
		go func(userPass Cred) {
			user, pass := userPass.user, userPass.pass
			log.Debugf("trying ssh with %s + %s on %s:%d", user, pass, host, port)
			err := scan(host, port, user, pass)
			if err == nil {
				log.Infof("ssh %s@%s -p %d # password=%s", user, host, port, pass)
				res.Vulnerable = true
				res.Details = fmt.Sprintf("ssh %s@%s -p %d # password=%s", user, host, port, pass)
			}
			wg.Done()
		}(u)
	}

	wg.Wait()
	return res
}

func New() scanner.Checker {
	return new(SSHChecker)
}