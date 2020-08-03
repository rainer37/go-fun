package secret

import (
	"fmt"
	"net/http"
)

const CredUser = "USER"
const CredSts = "STS"

type AWS struct {
	path string
	credType string
}

func NewAWS(path, credType string) *AWS {
	return &AWS{path, credType}
}

func (aws *AWS) GetDataPath(dataKey string) (string, error) {
	if aws.credType == CredUser {
		return fmt.Sprintf("v1/%s/creds/%s", aws.path, dataKey), nil
	}
	if aws.credType == CredSts {
		return fmt.Sprintf("v1/%s/sts/%s", aws.path, dataKey), nil
	}
	return "", fmt.Errorf("cannot generate secret data path")
}

func (aws *AWS) GetVerb() string {
	return http.MethodGet
}

func (aws *AWS) GetPathToValue(optionKey string) []string {
	if aws.credType == CredSts {
		return []string{"data", "access_key:secret_key:security_token"}
	}
	return []string{"data", "access_key:secret_key"}
}
