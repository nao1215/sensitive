//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// outputClosed reports a write to a pipe whose reader has gone. A write to
// standard output or standard error raises SIGPIPE first, so this is reached
// for other descriptors.
func outputClosed(err error) bool { return errors.Is(err, syscall.EPIPE) }
