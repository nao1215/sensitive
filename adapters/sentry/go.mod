module github.com/nao1215/embargo/adapters/sentry

go 1.26.11

replace github.com/nao1215/embargo => ../..

require (
	github.com/getsentry/sentry-go v0.50.0
	github.com/nao1215/embargo v0.5.1-0.20261116041606-5b9b76c91cd7
)

require (
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
