package scanner

type Checker interface {
	Check(host string, port uint64) *Result
}

type Result struct {
	Vulnerable bool
	Details string
}