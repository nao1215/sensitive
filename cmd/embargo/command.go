package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/nao1215/embargo"
)

// Exit statuses for a command that cannot start, as a shell reports them.
const (
	statusCannotRun = 126
	statusNotFound  = 127
	signalBase      = 128
)

// statusError ends embargo with code. cause, when set, is printed first.
type statusError struct {
	cause error
	code  int
}

// Error returns the cause, or a fixed text when there is none.
func (e statusError) Error() string {
	if e.cause == nil {
		return "embargo: the command failed"
	}
	return e.cause.Error()
}

// runCommand starts argv with input and the environment, masks its standard
// output onto output and its standard error onto diagnostics, each line by
// line as the filter does, and returns its status. A command ended by a
// signal reports 128 plus the signal, as a shell does.
//
// SIGTERM and SIGHUP sent to embargo are passed on and embargo goes on masking
// until the command ends. An interrupt from the terminal already reaches the
// command, which runs in the same process group, so embargo only stays alive
// for the output that follows it.
func runCommand(argv []string, scanner *embargo.Scanner, input io.Reader, output, diagnostics io.Writer) error {
	// #nosec G204 -- The user names the command to run on the command line.
	command := exec.CommandContext(context.Background(), argv[0], argv[1:]...)
	command.Stdin = input
	streams, err := commandStreams(command)
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(signals)
		close(signals)
	}()
	if err := command.Start(); err != nil {
		streams.close()
		return startFailure(err)
	}
	streams.closeChildEnds()
	go relaySignals(command.Process, signals)
	failures := streams.mask(scanner, output, diagnostics)
	return commandStatus(command.Wait(), failures)
}

// relaySignals passes SIGTERM and SIGHUP on to the command; an interrupt is
// only kept from ending embargo.
func relaySignals(process *os.Process, signals <-chan os.Signal) {
	for received := range signals {
		if received != os.Interrupt {
			_ = process.Signal(received) //nolint:errcheck // A command that has already ended needs no signal.
		}
	}
}

// startFailure maps a command that cannot start to 127 when it is not found
// and 126 otherwise, without repeating its name.
func startFailure(err error) error {
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return statusError{cause: errors.New("embargo: the command was not found"), code: statusNotFound}
	case errors.Is(err, fs.ErrPermission):
		return statusError{cause: errors.New("embargo: the command cannot be run: permission denied"), code: statusCannotRun}
	default:
		return statusError{cause: errors.New("embargo: the command cannot be run"), code: statusCannotRun}
	}
}

// commandStatus returns the command's status. A masking failure, such as an
// over-long line, is reported and turns a successful status into 1; a closed
// output ends quietly as the filter does.
func commandStatus(waitErr error, failures []error) error {
	code := 0
	if exit, ok := errors.AsType[*exec.ExitError](waitErr); ok {
		code = exit.ExitCode()
		if status, isWait := exit.Sys().(syscall.WaitStatus); isWait && status.Signaled() {
			code = signalBase + int(status.Signal())
		}
	} else if waitErr != nil {
		code = statusFailed
	}
	for _, failure := range failures {
		if errors.Is(failure, errOutputClosed) {
			return failure
		}
	}
	if failure := errors.Join(failures...); failure != nil {
		return statusError{cause: failure, code: max(code, statusFailed)}
	}
	if code != 0 {
		return statusError{cause: nil, code: code}
	}
	return nil
}

// commandPipes holds the read and write ends for the command's standard
// output and standard error.
type commandPipes struct {
	read, write [2]*os.File
}

// commandStreams connects the command's standard output and standard error
// to new pipes. The command writes to the pipes directly, and a process it
// leaves behind keeps them open, as it would keep a shell pipe open.
func commandStreams(command *exec.Cmd) (*commandPipes, error) {
	pipes := &commandPipes{}
	for i := range pipes.read {
		read, write, err := os.Pipe()
		if err != nil {
			pipes.close()
			return nil, errors.New("embargo: the command cannot be run: no pipe")
		}
		pipes.read[i], pipes.write[i] = read, write
	}
	command.Stdout, command.Stderr = pipes.write[0], pipes.write[1]
	return pipes, nil
}

// closeChildEnds closes this process's copies of the write ends once the
// command holds its own, so each read ends when the command closes them.
func (p *commandPipes) closeChildEnds() {
	for i, write := range p.write {
		if write != nil {
			_ = write.Close() //nolint:errcheck // The command holds its own copy; nothing was written here.
			p.write[i] = nil
		}
	}
}

func (p *commandPipes) close() {
	p.closeChildEnds()
	for _, read := range p.read {
		if read != nil {
			_ = read.Close() //nolint:errcheck // Nothing is read from a pipe that is closed unused.
		}
	}
}

// mask filters both streams at once and returns their failures. A stream
// that stops early is closed, so the command gets a broken pipe instead of
// blocking on a pipe nobody reads.
func (p *commandPipes) mask(scanner *embargo.Scanner, output, diagnostics io.Writer) []error {
	failures := make([]error, len(p.read))
	var group sync.WaitGroup
	for i, destination := range []io.Writer{output, diagnostics} {
		group.Go(func() {
			failures[i] = filterLines(p.read[i], destination, scanner)
			_ = p.read[i].Close() //nolint:errcheck // The stream was read to its end or abandoned.
		})
	}
	group.Wait()
	return failures
}
