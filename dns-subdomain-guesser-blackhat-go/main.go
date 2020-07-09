package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"text/tabwriter"

	"github.com/miekg/dns"
)

type result struct {
	IPAddress string
	Hostname string
}

type emptyStrut struct {}
type results []result

func lookupA(fqdn, dnsServer string) ([]string, error) {
	var ips []string
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(&msg, dnsServer)
	if err != nil {
		return ips, err
	}
	// log.Infof("%#v", in)

	if len(in.Answer) < 1 {
		return ips, errors.New("no answer")
	}

	for _, answer := range in.Answer {
		if ans, ok := answer.(*dns.A); ok {
			ips = append(ips, ans.A.String())
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
	// log.Infof("%#v", in)
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
	var cfqdn = fqdn
	for {
		cnames, err := lookupCNAME(cfqdn, dnsServer)
		if err == nil && len(cnames) > 0 {
			cfqdn = cnames[0]
			//log.Info("found next cname ", cfqdn)
			continue
		}
		ips, err := lookupA(cfqdn, dnsServer)
		if err != nil {
			// log.Error("No A record found at the end")
			break
		}
		for _, ip := range ips {
			answers = append(answers, result{
				IPAddress: ip,
				Hostname: fqdn,
			})
		}
		break // found the A
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

func main() {

	// lookup("buy.microsoft.com.cp.microsoft.com.nsatc.net", "8.8.8.8:53")

	// os.Exit(1)
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
	var finalResults results

	fh, err := os.Open(*wordList)
	if err != nil {
		log.Error(err)
	}
	defer fh.Close()

	for i := 0; i < *numWorkers; i++ {
		go worker(tracker, inputQueries, outputResults, *dnsServer)
	}

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		subdomain := fmt.Sprintf("%s.%s", scanner.Text(), *targetDomain)
		inputQueries <- subdomain
	}

	go func() {
		for res := range outputResults {
			finalResults = append(finalResults, res...)
		}
		resultReady <- emptyStrut{}
	}()

	close(inputQueries)
	for i := 0; i < *numWorkers; i++ {
		<-tracker
	}

	close(outputResults)
	close(tracker)

	<-resultReady
	close(resultReady)

	w := tabwriter.NewWriter(os.Stdout, 0, 8, ' ', ' ', 0)
	for _, res := range finalResults {
		fmt.Fprintf(w, "%s\t%s\n", res.Hostname, res.IPAddress)
	}
	w.Flush()
}