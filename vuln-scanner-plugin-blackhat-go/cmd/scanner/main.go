package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"plugin"

	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
)

var PluginsDir string

func init()  {
	PluginsDir = *flag.String("plugin-dir", "../../plugins", "the directory to find so files")
}

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
		soFile := files[idx].Name()
		if filepath.Ext(soFile) != ".so" {
			continue
		}

		log.Println("Found plugins: " + soFile)
		if p, err = plugin.Open(PluginsDir + "/" + soFile); err != nil {
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