package secret

import (
	"fmt"
	"net/http"
)

const (
	PurEncrypt = "encrypt"
	PurDecrypt = "decrypt"
	PurSign = "sign"
	PurVerify = "verify"
	PurHash = "hash"
	PurHMAC = "hmac"
	PurRand = "random"
	PurRotate = "keys"
)

var resultKey = map[string]string {
	PurEncrypt : "ciphertext",
	PurDecrypt : "plaintext",
	PurSign : "signature",
	PurVerify : "valid",
	PurHash : "sum",
	PurHMAC : "hmac",
	PurRand : "random_bytes",
}

type Transit struct {
	path string
	purpose string
}

func NewTransit(path, purpose string) *Transit {
	return &Transit{path, purpose}
}

func (transit *Transit) GetDataPath(dataKey string) (string, error) {
	return fmt.Sprintf("v1/%s/%s/%s", transit.path, transit.purpose, dataKey), nil
}

func (transit *Transit) GetVerb() string {
	return http.MethodPost
}

func (transit *Transit) GetPathToValue(optionKey string) []string {
	return []string{"data", resultKey[transit.purpose]}
}

func (transit *Transit) SetPurpose(purpose string) {
	transit.purpose = purpose
}