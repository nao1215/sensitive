module github.com/nao1215/sensitive/tests

go 1.26.0

replace github.com/nao1215/sensitive => ../

require (
	github.com/nao1215/sensitive v0.2.1
	golang.org/x/crypto v0.59.0
	pgregory.net/rapid v1.3.0
)

require golang.org/x/sys v0.50.0 // indirect
