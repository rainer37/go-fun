package client

type AuthInfo interface {
	ToPayload() string
}

const authMethodBase = "v1/auth/%s/"

var authMethodPathMap = map[string]string {
	"userpass": authMethodBase + "login/%s",
	"okta": authMethodBase + "login/%s",
	"default": authMethodBase + "login",
}

type VaultClient interface {
	GetCachedToken() string
	SetToken(token string) error
	Login(method string, args []string, path string, info AuthInfo) (string, error)
}

type ServerInfo struct {
	Addr string
}
