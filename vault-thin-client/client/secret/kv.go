package secret

import "fmt"

type KV struct {
	path string
}

func NewKV(path string) *KV {
	return &KV{path}
}

func (kv *KV) GetDataPath(dataKey string) (string, error) {
	return fmt.Sprintf("v1/%s/data/%s", kv.path, dataKey), nil
}

func (kv *KV) GetVerb() string {
	return "GET"
}

func (kv *KV) GetPathToValue(optionKey string) []string {
	return []string{"data", "data", optionKey}
}