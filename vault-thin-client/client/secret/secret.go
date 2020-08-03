package secret

import "io"

type Engine interface {
	io.Reader
}

func MakeEngine(engine string) *Engine {
	return nil
}