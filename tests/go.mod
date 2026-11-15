module github.com/nao1215/embargo/tests

go 1.26.0

replace github.com/nao1215/embargo => ../

require (
	github.com/nao1215/embargo v0.2.1
	golang.org/x/crypto v0.59.0
	pgregory.net/rapid v1.3.0
)

require golang.org/x/sys v0.50.0 // indirect
