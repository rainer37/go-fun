package main

import (
	"context"
	"github.com/rainer37/go-fun/grpc-rat-black-hat-go/grpcapi"
)

type implantServer struct {
	work, output chan *grpcapi.Command
}

type adminServer struct {
	work, output chan *grpcapi.Command
}

func NewImplantServer(work, out chan *grpcapi.Command) *implantServer {
	s := new(implantServer)
	s.work, s.output = work, out
	return s
}

func NewAdminServer(work, out chan *grpcapi.Command) *adminServer {
	a := new(adminServer)
	a.work, a.output = work, out
	return a
}

func (s* implantServer) SendOutputs(ctx context.Context, result *grpcapi.Command) (*grpcapi.Empty, error) {
	return nil, nil
}