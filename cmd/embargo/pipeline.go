package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"runtime"

	"github.com/nao1215/embargo"
)

// Batches bound what one worker takes at a time and how much input waits.
const (
	batchBytes  = 256 << 10
	readBuffer  = 1 << 20
	batchFactor = 2
)

// batch is a run of consecutive lines read together. Workers scan batches in
// parallel, each from a fresh scanner state; the writer takes them in input
// order and scans one again from the true state when the line before it left
// a PEM block, a JSON document, a YAML block or a quoted field open.
type batch struct {
	end     *lineScanner
	failure error
	done    chan struct{}
	data    []byte
	// ends holds where each line, with its ending, stops in data.
	ends   []int
	out    []byte
	found  []located
	offset int64
	first  int
	// flush is set when no more input was buffered after the last line.
	flush bool
}

// located is a finding with the number of its line and where that line
// starts in the input.
type located struct {
	finding embargo.Finding
	offset  int64
	line    int
}

// lineRenderer turns the lines of a batch into its output or findings.
type lineRenderer func(lines *lineScanner, b *batch)

// pipeline reads lines exactly as the filter always has: a line may hold up
// to 4 MiB, and a read failure or a longer line ends the input after the
// lines before it, with a message that names the line and ends with
// consequence.
type pipeline struct {
	base        *lineScanner
	render      lineRenderer
	consequence string
	// lines and size count the non-empty lines and bytes read.
	lines int
	size  int64
}

// run reads input, renders batches on every CPU and passes each batch to emit
// in input order; emit returns an error to stop. The error of the input, if
// any, comes after every batch before it.
func (p *pipeline) run(input io.Reader, emit func(*batch) error) error {
	workers := runtime.GOMAXPROCS(0)
	work := make(chan *batch, batchFactor*workers)
	ordered := make(chan *batch, batchFactor*workers)
	quit := make(chan struct{})
	defer close(quit)
	for range workers {
		go func() {
			for b := range work {
				lines := p.base.fork()
				p.render(lines, b)
				b.end = lines
				close(b.done)
			}
		}()
	}
	go p.read(bufio.NewReaderSize(input, readBuffer), work, ordered, quit)
	state := p.base
	for b := range ordered {
		<-b.done
		if !state.neutral(p.base) {
			b.out, b.found = b.out[:0], b.found[:0]
			p.render(state, b)
			b.end = state
		}
		state = b.end
		if err := emit(b); err != nil {
			return err
		}
		if b.failure != nil {
			return b.failure
		}
	}
	return nil
}

// read splits input into batches and sends each to a worker and, in order,
// to the writer, until the input ends or fails.
func (p *pipeline) read(reader *bufio.Reader, work, ordered chan<- *batch, quit <-chan struct{}) {
	defer close(work)
	defer close(ordered)
	number := 1
	for {
		b := &batch{first: number, offset: p.size, done: make(chan struct{})}
		done := p.fill(reader, b)
		number = b.first + len(b.ends)
		if !send(work, b, quit) || !send(ordered, b, quit) || done || b.failure != nil {
			return
		}
	}
}

// fill reads lines into b until batchBytes or until no more input is
// buffered, so a slow pipe's line is passed on without waiting for the next,
// and reports whether the input ended.
func (p *pipeline) fill(reader *bufio.Reader, b *batch) bool {
	done := false
	for !done && len(b.data) < batchBytes {
		line, tooLong, readErr := readLine(reader)
		if b.failure = readFailure(tooLong, readErr, b.first+len(b.ends), p.consequence); b.failure != nil {
			break
		}
		if len(line) > 0 {
			p.lines++
			b.data = append(b.data, line...)
			b.ends = append(b.ends, len(b.data))
			p.size += int64(len(line))
			p.header(b)
		}
		done = errors.Is(readErr, io.EOF)
		if reader.Buffered() == 0 {
			break
		}
	}
	b.flush = done || b.failure != nil || reader.Buffered() == 0
	return done
}

// header gives a table's base the column names of the first line, so the
// workers start from them.
func (p *pipeline) header(b *batch) {
	if p.base.table != nil && p.base.table.header == nil && len(b.ends) == 1 {
		body, _ := splitEnding(b.data)
		p.base.table.findings(bytes.TrimPrefix(body, []byte(utf8BOM)))
	}
}

func send(channel chan<- *batch, b *batch, quit <-chan struct{}) bool {
	select {
	case channel <- b:
		return true
	case <-quit:
		return false
	}
}

// each calls fn with the number, input offset and bytes, ending included,
// of every line of b.
func (b *batch) each(fn func(number int, offset int64, line []byte)) {
	start := 0
	for i, end := range b.ends {
		fn(b.first+i, b.offset+int64(start), b.data[start:end])
		start = end
	}
}

// fork returns a fresh scanner state that starts where base is: with no open
// block, and with the column names of a table.
func (l *lineScanner) fork() *lineScanner {
	forked := newLineScanner(l.scanner, inputLines)
	if l.table != nil {
		forked.table = newTable(l.scanner, l.table.delimiter)
		forked.table.header, forked.table.raw = l.table.header, l.table.raw
	}
	return forked
}

// neutral reports whether l is in the state a fork of base starts in, so a
// batch scanned from that fork needs no second scan.
func (l *lineScanner) neutral(base *lineScanner) bool {
	if l.open() {
		return false
	}
	return l.table == nil || (!l.table.quoted && bytes.Equal(l.table.raw, base.table.raw))
}
