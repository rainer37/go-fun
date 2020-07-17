package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

const (
	certDir = "certs"
	clientCertFile = certDir + "/clientCrt.pem"
	serverCertFile = certDir + "/serverCrt.pem"
	serverKeyFile = certDir + "/serverKey.pem"
)

var (
	listenAddr string
	listenPort string
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("Hello ", r.TLS.PeerCertificates[0].Subject.CommonName)
	fmt.Fprintln(w, "AuthN successfully: ", r.RemoteAddr)
}

func init() {
	flag.StringVar(&listenAddr, "addr", "", "address to listen for HTTPS requests")
	flag.StringVar(&listenPort, "port", "443", "port for TLS connection")
	flag.Parse()
}

func main() {
	log.Infof("HTTPS server started on %s:%s", listenAddr, listenPort)

	http.HandleFunc("/hello", helloHandler)

	clientCert, err := ioutil.ReadFile(clientCertFile)
	if err != nil {
		log.Fatalln(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(clientCert)

	tlsConfig := &tls.Config{
		ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr: listenAddr+":"+listenPort,
		TLSConfig: tlsConfig,
	}
	log.Fatalln(server.ListenAndServeTLS(serverCertFile, serverKeyFile))
}