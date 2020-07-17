package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

const (
	certDir = "certs"
	clientCertFile = certDir + "/clientCrt.pem"
	clientKeyFile = certDir + "/clientKey.pem"
	serverCertFile = certDir + "/../../server/certs/serverCrt.pem"
)

var (
	serverAddr string
	serverPort string
)

func init() {
	flag.StringVar(&serverAddr, "addr", "", "address to listen for HTTPS requests")
	flag.StringVar(&serverPort, "port", "443", "port for TLS connection")
	flag.Parse()
}

func main() {
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	serverCert, err := ioutil.ReadFile(serverCertFile)
	if err != nil {
		log.Fatalln(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(serverCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs: pool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://" + serverAddr + ":" + serverPort + "/hello")
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	log.Infof("Success: %s", body)
}