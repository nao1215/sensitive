module github.com/nao1215/sensitive/tests

go 1.23.0

replace github.com/nao1215/sensitive => ../

require (
	github.com/nao1215/sensitive v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.41.0
	pgregory.net/rapid v1.3.0
)

require golang.org/x/sys v0.35.0 // indirect
