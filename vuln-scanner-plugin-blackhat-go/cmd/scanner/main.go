package main

import (
	"io/ioutil"
	"log"
	"os"
	"plugin"

	//"../../scanner"

	"github.com/rainer37/go-fun/vuln-scanner-plugin-blackhat-go/scanner"
)

const PluginsDir = "../../plugins"

func main() {
	var (
		files []os.FileInfo
		err error
		p *plugin.Plugin
		n plugin.Symbol
		check scanner.Checker
		res *scanner.Result
	)

	if files, err = ioutil.ReadDir(PluginsDir); err != nil {
		log.Fatalln(err)
	}

	for idx := range files {
		log.Println("Found plugins: " + files[idx].Name())
		if p, err = plugin.Open(PluginsDir + "/" + files[idx].Name()); err != nil {
			log.Fatalln(err)
		}

		if n, err = p.Lookup("New"); err != nil {
			log.Fatalln(err)
		}

		newFunc, ok := n.(func() scanner.Checker)
		if !ok {
			log.Fatalln("Plugin entry point is no good. Expecting: func New() scanner.Checker")
		}

		check = newFunc()
		res = check.Check("10.0.1.20", 8080)
		if res.Vulnerable {
			log.Println("Host is vulnerable: " + res.Details)
		} else {
			log.Println("Host is NOT vulnerable")
		}
	}
}