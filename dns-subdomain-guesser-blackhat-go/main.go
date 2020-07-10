package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type result struct {
	IPAddress string
	Hostname string
	PathToA []string
}

type emptyStrut struct {}
type results []result

type Cache struct {
	cache map[string]string
	lock sync.RWMutex
}

var ACache Cache

func lookupA(fqdn, dnsServer string) (string, error) {
	var ips string
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)

	in, err := dns.Exchange(&msg, dnsServer)
	if err != nil {
		return ips, err
	}

	if len(in.Answer) < 1 {
		return ips, errors.New("no answer")
	}

	for _, answer := range in.Answer {
		if ans, ok := answer.(*dns.A); ok {
			ips = ans.A.String() // assume there is only one A
			return ips, nil
		}
	}
	return ips, nil
}

func lookupCNAME(fqdn, dnsServer string) ([]string, error) {
	var cnames []string
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)

	in, err := dns.Exchange(&msg, dnsServer)
	if err != nil {
		return cnames, err
	}

	if len(in.Answer) < 1 {
		return cnames, errors.New("no answer")
	}

	for _, answer := range in.Answer {
		if ans, ok := answer.(*dns.CNAME); ok {
			cnames = append(cnames, ans.Target)
		}
	}
	return cnames, nil
}

func lookup(fqdn, dnsServer string) results {
	var answers results
	var pathToA []string
	var cfqdn = fqdn

	for {
		pathToA = append(pathToA, cfqdn)
		ACache.lock.Lock()
		if cachedAddr, ok := ACache.cache[cfqdn]; ok {
			log.Debugf("cache hit while looking for %s => %s", cfqdn, cachedAddr)
			answers = append(answers, result{
				IPAddress: cachedAddr,
				Hostname: fqdn,
				PathToA: pathToA,
			})
			ACache.lock.Unlock()
			break
		}
		ACache.lock.Unlock()

		cnames, err := lookupCNAME(cfqdn, dnsServer)
		if err == nil && len(cnames) > 0 {
			cfqdn = cnames[0]
			//log.Info("found next cname ", cfqdn)
			continue
		}

		ip, err := lookupA(cfqdn, dnsServer)
		if err != nil {
			if log.GetLevel() == log.DebugLevel {
				answers = append(answers, result{
					IPAddress: "",
					Hostname:  fqdn,
					PathToA:   append(pathToA, "NOTHING"),
				})
			}
			break
		}

		answers = append(answers, result{
			IPAddress: ip,
			Hostname: fqdn,
			PathToA: pathToA,
		})

		// populate cache
		ACache.lock.Lock()
		for _, path := range pathToA {
			if cachedAddr, ok := ACache.cache[path]; ok && cachedAddr != ip {
				log.Debugf("interesting, different A destination found %s: [%s, %s]", path, cachedAddr, ip)
			} else {
				log.Debugf("Caching %s => %s", path, ip)
				ACache.cache[path] = ip
			}
		}
		ACache.lock.Unlock()

		break // found the final A
	}
	return answers
}

func worker(tracker chan<- emptyStrut, inputQueries <-chan string, outputResults chan<- results, dnsServer string) {
	// log.Infof("worker stared using %s", dnsServer)
	for fqdn := range inputQueries {
		answer := lookup(fqdn, dnsServer)
		if len(answer) > 0 {
			outputResults <- answer
		}
	}
	tracker <- emptyStrut{}
}

func init() {
	ACache = Cache{make(map[string]string), sync.RWMutex{}} // A record cache
	// log.SetLevel(log.DebugLevel)
}

func main() {
	var (
		targetDomain = flag.String("target-domain", "", "target main FQDN to search subdomians")
		dnsServer    = flag.String("dns-server", "8.8.8.8:53", "designated DNS server address to use")
		wordList     = flag.String("wordlist", "", "a word list of subdomains to search for")
		numWorkers   = flag.Int("num-workers", 100, "capacity of Workers in worker pool to perform DNS queries")
	)
	flag.Parse()
	log.Infof("Guessing subdomains on [%s] through DNS server [%s], " +
		"with [%d] workers using words from [%s]", *targetDomain, *dnsServer, *numWorkers, *wordList)

	if *targetDomain == "" || *wordList == "" {
		log.Error("required args: -targetDomain and -wordlist")
	}

	tracker := make(chan emptyStrut) // tracking working progress
	resultReady := make(chan emptyStrut) // block waiting on final results
	inputQueries := make(chan string, *numWorkers) // send queries to workers
	outputResults := make(chan results) // gather query results from workers
	//var finalResults results

	fh, err := os.Open(*wordList)
	if err != nil {
		log.Error(err)
	}
	defer fh.Close()
	scanner := bufio.NewScanner(fh)

	for i := 0; i < *numWorkers; i++ {
		go worker(tracker, inputQueries, outputResults, *dnsServer)
	}

	go func() {
		for one := range outputResults {
			for _, res := range one {
				log.Infof("%s\t\t%s\n", res.IPAddress, strings.Join(res.PathToA, " => "))
			}
		}
		resultReady <- emptyStrut{}
	}()

	for scanner.Scan() {
		subdomain := fmt.Sprintf("%s.%s", scanner.Text(), *targetDomain)
		inputQueries <- subdomain
	}
	close(inputQueries)

	for i := 0; i < *numWorkers; i++ {
		<-tracker
	}
	close(outputResults)
	close(tracker)

	<-resultReady
	close(resultReady)
}