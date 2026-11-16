module github.com/nao1215/embargo/adapters/grpc

go 1.26.11

replace github.com/nao1215/embargo => ../..

require (
	github.com/nao1215/embargo v0.5.2
	google.golang.org/grpc v1.85.0
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
