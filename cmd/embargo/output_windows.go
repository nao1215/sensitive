//go:build windows

package main

import (
	"errors"
	"syscall"
)

// Windows reports a pipe whose reader has gone as ERROR_BROKEN_PIPE, or as
// ERROR_NO_DATA while the pipe is being closed; it has no SIGPIPE.
const (
	errorBrokenPipe = syscall.Errno(109)
	errorNoData     = syscall.Errno(232)
)

// outputClosed reports a write to a pipe whose reader has gone.
func outputClosed(err error) bool {
	return errors.Is(err, errorBrokenPipe) || errors.Is(err, errorNoData) || errors.Is(err, syscall.EPIPE)
}
