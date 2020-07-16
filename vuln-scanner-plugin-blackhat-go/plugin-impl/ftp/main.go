package main

import (
	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
	"log"
)

type FTPChecker struct {}

func (sc *FTPChecker) Check(host string, port uint64) *scanner.Result {
	res := new(scanner.Result)
	log.Println("Checking FTP server")
	return res
}

func New() scanner.Checker {
	return new(FTPChecker)
}