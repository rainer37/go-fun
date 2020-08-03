package client

type VaultClient interface {
	getToken() string
	setToken(token string) error
}

type ServerInfo struct {
	Addr string
}
