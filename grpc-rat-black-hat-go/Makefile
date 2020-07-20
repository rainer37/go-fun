all:
	rm grpcapi/*.pb.go
	protoc grpcapi/implant.proto --proto_path=grpcapi --go_opt=paths=source_relative  --go_out=grpcapi