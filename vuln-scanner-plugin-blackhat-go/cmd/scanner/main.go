package main

import (
	"flag"
	"log"
	"plugin"
	"strconv"
	"strings"
	"sync"

	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
)

var (
	PluginsDir *string
	hosts *string
	ports *string
	wg sync.WaitGroup
)

var scannerMap = map[uint64] string {
	21: "ftp.so",
	22: "ssh.so",
	2222: "ssh.so",
	8080: "tomcat.so",
	80: "tomcat.so",
}

func init()  {
	PluginsDir = flag.String("plugin-dir", "../../plugins", "the directory to find so files")
	hosts = flag.String("hosts", "10.0.1.20,10.0.2.88", "host address list to scan")
	ports = flag.String("ports", "8080,80", "interested port number list")
	flag.Parse()
	log.Println(*PluginsDir, *hosts, *ports)
}

func loadScanner(port uint64) scanner.Checker {
	soFile, ok := scannerMap[port]
	if !ok {
		log.Fatalln("no such plan for port ", port)
	}

	p, err := plugin.Open(*PluginsDir + "/" + soFile)
	if err != nil {
		log.Fatalln(err)
	}

	n, err := p.Lookup("New")
	if err != nil {
		log.Fatalln(err)
	}

	newFunc, ok := n.(func() scanner.Checker)
	if !ok {
		log.Fatalln("Plugin entry point is no good. Expecting: func New() scanner.Checker")
	}

	return newFunc()
}

func scan(host string, portString string)  {
	log.Printf("Scanning [%s:%s]", host, portString)

	defer wg.Done()

	port, err := strconv.ParseUint(portString, 10, 64)
	if err != nil {
		log.Fatalln(err)
	}
	checker := loadScanner(port)
	res := checker.Check(host, port)

	if res.Vulnerable {
		log.Println(host, "Host is vulnerable: " + res.Details)
	} else {
		log.Println(host, ", Host is NOT vulnerable")
	}
}

func main() {
	log.Println("start scanning...")
	for _, host := range strings.Split(*hosts, ",") {
		for _, portString := range strings.Split(*ports, ",") {
			wg.Add(1)
			go scan(host, portString)
		}
	}
	wg.Wait()
}