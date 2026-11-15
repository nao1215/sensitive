module github.com/nao1215/embargo/adapters/zap

go 1.26.11

replace github.com/nao1215/embargo => ../..

require (
	github.com/nao1215/embargo v0.3.1-0.20261115073836-fdc34eb3b8bb
	go.uber.org/zap v1.28.0
)

require go.uber.org/multierr v1.10.0 // indirect
