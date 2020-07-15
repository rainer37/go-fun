package main

import (
	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
	"log"
)

type SSHChecker struct {}

func (sc *SSHChecker) Check(host string, port uint64) *scanner.Result {
	res := new(scanner.Result)
	log.Println("Checking SSH server")
	return res
}

func New() scanner.Checker {
	return new(SSHChecker)
}