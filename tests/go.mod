module github.com/nao1215/embargo/tests

go 1.26.11

replace github.com/nao1215/embargo => ../

require (
	github.com/nao1215/embargo v0.2.1
	golang.org/x/crypto v0.59.0
	golang.org/x/tools v0.52.0
	pgregory.net/rapid v1.3.0
)

require (
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
