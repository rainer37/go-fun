package main

import (
	"github.com/rainer37/go-fun/vuln-scanner-plugin-blackhat-go/scanner"
)

type TomcatChecker struct {}

func (tc *TomcatChecker) Check(host string, port uint64) *scanner.Result {
	res := new(scanner.Result)
	return res
}

func New() scanner.Checker {
	return new(TomcatChecker)
}