package secret

type Engine interface {
	GetDataPath(dataKey string) (string, error)
	GetVerb() string
	GetPathToValue(optionKey string) []string
}
