package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
)

const (
	certDir = "certs"
	clientCertFile = certDir + "/../../client/certs/clientCrt.pem"
	serverCertFile = certDir + "/serverCrt.pem"
	serverKeyFile = certDir + "/serverKey.pem"
)

var (
	listenAddr string
	listenPort string
	proto string
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("Hello %#v", r.TLS.PeerCertificates[0].Subject.CommonName)
	fmt.Fprintln(w, "AuthN successfully: ", r.RemoteAddr)
}

func helloHandlerTCP(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		err := tlsConn.Handshake()
		if err != nil {
			log.Fatalln(err)
		}
		state := tlsConn.ConnectionState()
		log.Infof("Hello %#v", state.PeerCertificates[0].Subject.CommonName)
		fmt.Fprintln(conn, "AuthN successfully: ", conn.RemoteAddr())
	}
}

func init() {
	flag.StringVar(&listenAddr, "addr", "", "address to listen for HTTPS requests")
	flag.StringVar(&listenPort, "port", "443", "port for TLS connection")
	flag.StringVar(&proto, "proto", "HTTPS", "protocol to serve, TCP or HTTPS")
	flag.Parse()
}

func serveTCP(tlsConfig *tls.Config) {
	listener, err := tls.Listen("tcp", listenAddr+":"+listenPort, tlsConfig)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("TCP server started on %s:%s", listenAddr, listenPort)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		go helloHandlerTCP(conn)
	}
}

func serveHTTPS(tlsConfig *tls.Config) {
	http.HandleFunc("/hello", helloHandler)
	server := &http.Server{
		Addr: listenAddr+":"+listenPort,
		TLSConfig: tlsConfig,
	}
	log.Infof("HTTPS server started on %s:%s", listenAddr, listenPort)
	log.Fatalln(server.ListenAndServeTLS("", ""))
}

func main() {
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	clientCert, err := ioutil.ReadFile(clientCertFile)
	if err != nil {
		log.Fatalln(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(clientCert)

	tlsConfig := &tls.Config{
		ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
	}

	switch proto {
	case "HTTPS":
		serveHTTPS(tlsConfig)
	case "TCP":
		serveTCP(tlsConfig)
	default:
		log.Error("Unknown protocol, exit...")
	}
}

// go run server.go -addr localhost -port 9000 -proto TCP