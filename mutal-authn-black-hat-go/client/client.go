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
	proto string
)

func init() {
	flag.StringVar(&serverAddr, "addr", "", "address to listen for HTTPS requests")
	flag.StringVar(&serverPort, "port", "443", "port for TLS connection")
	flag.StringVar(&proto, "proto", "HTTPS", "protocol to serve, TCP or HTTPS")
	flag.Parse()
}

func tryHTTPS(tlsConfig *tls.Config) {
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

func tryTCP(tlsConfig *tls.Config) {
	conn, err := tls.Dial("tcp", serverAddr+":"+serverPort, tlsConfig)
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()
	log.Info("connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Debugf("server CNAME: %s", state.PeerCertificates[0].Subject.CommonName)
	log.Debug("client: handshake: ", state.HandshakeComplete)
	log.Debug("client: mutual: ", state.NegotiatedProtocolIsMutual)

	reply := make([]byte, 256)
	n, err := conn.Read(reply)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("Got: %q (%d bytes)", string(reply[:n]), n)
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

	switch proto {
	case "HTTPS":
		tryHTTPS(tlsConfig)
	case "TCP":
		tryTCP(tlsConfig)
	default:
		log.Error("Unknown protocol, exit...")
	}
}

// go run client.go -addr localhost -port 9000