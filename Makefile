

	protoc -I=protos/ --go_out=protos/main --go-grpc_out=protos/main protos/app.proto