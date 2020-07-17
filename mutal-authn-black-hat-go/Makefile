server_cert_dir=server/certs
client_cert_dir=client/certs

certs: clean
	mkdir $(server_cert_dir) $(client_cert_dir)
	openssl req -nodes -x509 -newkey rsa:4096 -keyout $(server_cert_dir)/serverKey.pem -out $(server_cert_dir)/serverCrt.pem -days 365 -subj "/C=CA/ST=BC/L=Van/O=Global Sec/OU=IT/CN=localhost"
	openssl req -nodes -x509 -newkey rsa:4096 -keyout $(client_cert_dir)/clientKey.pem -out $(client_cert_dir)/clientCrt.pem -days 365 -subj "/C=CA/ST=BC/L=Van/O=Global Sec/OU=IT/CN=client.example.com"

test:
	curl -ik -X GET --cert $(client_cert_dir)/clientCrt.pem --key $(client_cert_dir)/clientKey.pem https://localhost:9000/hello

clean:
	rm -rf $(server_cert_dir) $(client_cert_dir)