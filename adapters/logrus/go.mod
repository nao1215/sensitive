module github.com/nao1215/embargo/adapters/logrus

go 1.26.11

replace github.com/nao1215/embargo => ../..

require (
	github.com/nao1215/embargo v0.3.1-0.20261115120736-66099c0624d2
	github.com/sirupsen/logrus v1.10.2
)

require golang.org/x/sys v0.50.0 // indirect
