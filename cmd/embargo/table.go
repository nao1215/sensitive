package main

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/nao1215/embargo"
)

// Input modes for --input.
const (
	inputLines = "lines"
	inputCSV   = "csv"
	inputTSV   = "tsv"
)

// inputMode returns --input when it is set, and otherwise csv or tsv when
// every named file has that extension, before an optional .gz or .bz2.
func inputMode(flagValue string, files []string) string {
	if flagValue != "" {
		return flagValue
	}
	mode := ""
	for _, name := range files {
		lower := strings.ToLower(name)
		lower = strings.TrimSuffix(strings.TrimSuffix(lower, ".gz"), ".bz2")
		extension := strings.TrimPrefix(filepath.Ext(lower), ".")
		if (extension != inputCSV && extension != inputTSV) || (mode != "" && mode != extension) {
			return inputLines
		}
		mode = extension
	}
	if mode == "" {
		return inputLines
	}
	return mode
}

// table reads CSV or TSV records line by line. The first line is the header,
// and a later line equal to it, as when files are concatenated, is a header
// again. Each field gets the findings of its column name as a key, as MaskJSON
// gives a member, so a password column is masked although its values look
// like any text. A quoted field may hold the delimiter, doubled quotes and
// line breaks; a field continued on the next line keeps its column.
type table struct {
	structure *structure
	header    []string
	raw       []byte
	delimiter byte
	// quoted is set while a quoted field continues past the end of a line,
	// in column.
	quoted bool
	column int
}

func newTable(scanner *embargo.Scanner, delimiter byte) *table {
	return &table{structure: newStructure(scanner), header: nil, raw: nil, delimiter: delimiter, quoted: false, column: 0}
}

// findings returns the findings that the column names add to one line.
func (t *table) findings(body []byte) []embargo.Finding {
	if line := bytes.TrimPrefix(body, []byte(utf8BOM)); !t.quoted && (t.header == nil || bytes.Equal(line, t.raw)) {
		// A spreadsheet writes a byte order mark before the header.
		t.raw = bytes.Clone(line)
		t.header = t.names(line)
		return nil
	}
	var found []embargo.Finding
	t.fields(body, func(column, start, end int) {
		if column < len(t.header) && t.header[column] != "" {
			found = t.structure.value(found, t.header[column], body[start:end], start, false)
		}
	})
	return found
}

// names returns the header's column names without quotes.
func (t *table) names(body []byte) []string {
	var names []string
	t.fields(body, func(_, start, end int) {
		names = append(names, strings.TrimSpace(strings.ReplaceAll(string(body[start:end]), `""`, `"`)))
	})
	t.quoted, t.column = false, 0
	return names
}

// fields calls fn with the column and the span of each field's value on the
// line, inside its quotes, and carries a quoted field that the line does
// not close to the next line.
func (t *table) fields(body []byte, fn func(column, start, end int)) {
	column, i := 0, 0
	if t.quoted {
		column = t.column
		end, closed := quotedEnd(body, 0)
		fn(column, 0, end)
		if !closed {
			return
		}
		t.quoted = false
		i = t.fieldEnd(body, end+1)
		if i >= len(body) {
			return
		}
		column, i = column+1, i+1
	}
	for {
		if i < len(body) && body[i] == '"' {
			end, closed := quotedEnd(body, i+1)
			fn(column, i+1, end)
			if !closed {
				t.quoted, t.column = true, column
				return
			}
			i = t.fieldEnd(body, end+1)
		} else {
			end := t.fieldEnd(body, i)
			fn(column, i, end)
			i = end
		}
		if i >= len(body) {
			return
		}
		column, i = column+1, i+1
	}
}

// fieldEnd returns the index of the next delimiter at or after i, or the
// line's length.
func (t *table) fieldEnd(body []byte, i int) int {
	if next := bytes.IndexByte(body[i:], t.delimiter); next >= 0 {
		return i + next
	}
	return len(body)
}

// quotedEnd returns the index of the quote that closes a field whose value
// starts at i, skipping doubled quotes, or the line's length and false when
// the field continues on the next line.
func quotedEnd(body []byte, i int) (int, bool) {
	for i < len(body) {
		next := bytes.IndexByte(body[i:], '"')
		if next < 0 {
			return len(body), false
		}
		i += next
		if i+1 < len(body) && body[i+1] == '"' {
			i += 2
			continue
		}
		return i, true
	}
	return len(body), false
}
