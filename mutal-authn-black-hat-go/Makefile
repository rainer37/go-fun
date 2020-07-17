certDir=certs

certs:
	rm -rf $(certDir)
	mkdir $(certDir)
	openssl req -nodes -x509 -newkey rsa:4096 -keyout $(certDir)/serverKey.pem -out $(certDir)/serverCrt.pem -days 365 -subj "/C=CA/ST=BC/L=Van/O=Global Sec/OU=IT/CN=server.example.com"
	openssl req -nodes -x509 -newkey rsa:4096 -keyout $(certDir)/clientKey.pem -out $(certDir)/clientCrt.pem -days 365 -subj "/C=CA/ST=BC/L=Van/O=Global Sec/OU=IT/CN=client.example.com"