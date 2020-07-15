package main

import (
	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
	"log"
)

type TomcatChecker struct {}

func (tc *TomcatChecker) Check(host string, port uint64) *scanner.Result {
	res := new(scanner.Result)
	log.Println("Checking Tomcat Manager login portal")
	return res
}

func New() scanner.Checker {
	return new(TomcatChecker)
}