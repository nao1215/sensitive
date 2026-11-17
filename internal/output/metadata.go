package output

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/nao1215/embargo/internal/saferecord"
)

// eventMetadata observes top-level fields while an oversized record is discarded.
// Only an allowlisted level enum survives; byte writers cannot authenticate an
// encoder timestamp or its configured field, so all time fields are omitted.
// This is not the
// JSON validator used to approve normal records. Incomplete input counts only
// attributes whose key and colon arrived before Flush or Close.
const (
	metadataTokenLimit = 96
	messageField       = "message"
)

type eventMetadata struct {
	prefix       []byte
	key          string
	messageKey   string
	token        []byte
	level        json.RawMessage
	depth        int
	count        int
	prefixFields int
	prefixDone   bool
	quoted       bool
	escaped      bool
	readingKey   bool
	wantKey      bool
}

func (m *eventMetadata) feed(data []byte) {
	for _, c := range data {
		m.consoleByte(c)
		m.byte(c)
	}
}

func (m *eventMetadata) byte(c byte) {
	if m.quoted {
		m.stringByte(c)
		return
	}

	if c == '"' {
		m.startString(c)
		return
	}
	switch c {
	case '{', '[':
		m.depth++
		if m.depth == 1 && c == '{' {
			m.wantKey = true
		}
	case '}', ']':
		m.closeContainer()
	case ':':
		if m.depth == 1 {
			m.endKey()
		}
	case ',':
		if m.depth == 1 {
			m.nextField()
		}
	case ' ', '\t', '\r', '\n':
	default:
		if m.depth == 1 && !m.wantKey {
			m.capture(c)
		}
	}
}

// startString opens a string token; at the top level it is the next key only
// while a key is expected.
func (m *eventMetadata) startString(c byte) {
	m.quoted = true
	m.readingKey = m.depth == 1 && m.wantKey
	m.token = nil
	m.capture(c)
}

// closeContainer leaves one nesting level; closing the top-level object also
// finishes its last value.
func (m *eventMetadata) closeContainer() {
	if m.depth == 1 {
		m.value()
	}
	m.depth--
}

// endKey starts a top-level value. Fixed time, level and message keys are not
// counted as withheld attributes; a "message" key selects that diagnostic field.
func (m *eventMetadata) endKey() {
	m.wantKey = false
	m.token = nil
	switch m.key {
	case "time", "ts", "timestamp", "level", "msg", messageField:
	default:
		m.count++
	}
	if m.key == messageField {
		m.messageKey = messageField
	}
}

// nextField finishes a top-level value at a comma and expects the next key.
func (m *eventMetadata) nextField() {
	m.value()
	m.wantKey = true
	m.key = ""
	m.token = nil
}

func (m *eventMetadata) stringByte(c byte) {
	m.capture(c)
	if m.escaped {
		m.escaped = false
		return
	}
	if c == '\\' {
		m.escaped = true
		return
	}
	if c != '"' {
		return
	}
	m.quoted = false
	if m.depth == 1 {
		m.endString()
	}
	m.token = nil
}

func (m *eventMetadata) endString() {
	if !m.readingKey {
		m.value()
		return
	}
	m.key = ""
	if len(m.token) <= metadataTokenLimit {
		if err := json.Unmarshal(m.token, &m.key); err != nil {
			m.key = ""
		}
	}
}

func (m *eventMetadata) capture(c byte) {
	const tokenLimit = metadataTokenLimit + 1
	if m.depth == 1 && len(m.token) < tokenLimit {
		m.token = append(m.token, c)
	}
}

func (m *eventMetadata) value() {
	if len(m.token) == 0 || len(m.token) > metadataTokenLimit {
		return
	}
	if m.key == "level" && m.level == nil {
		var text string
		if json.Unmarshal(m.token, &text) == nil {
			switch strings.ToLower(text) {
			case "trace", "debug", "info", "warn", "warning", "error", "dpanic", "panic", "fatal":
				m.level = append(json.RawMessage(nil), m.token...)
			}
		}
	}
}

func (m *eventMetadata) fallback(reason saferecord.SanitizationError) []byte {
	messageKey := m.messageKey
	if messageKey == "" {
		messageKey = "msg"
	}
	// Every string here is fixed or an allowlisted enum; retained JSON metadata was validated.
	out := []byte("{")
	if m.level != nil {
		out = append(out, `"level":`...)
		out = append(out, m.level...)
		out = append(out, ',')
	}
	out = append(out, '"')
	out = append(out, messageKey...)
	out = append(out, `":"`...)
	out = append(out, saferecord.Message(reason)...)
	out = append(out, `","withheld_attributes":`...)
	const decimalBase = 10
	out = strconv.AppendInt(out, int64(m.count), decimalBase)
	return append(out, '}', '\n')
}

// Standard zap console encoders put the level before the message, with an optional
// timestamp first. Only enum tokens survive; text and timestamps never do.
func (m *eventMetadata) consoleByte(c byte) {
	if m.prefixDone {
		return
	}
	if c == '{' || c == '[' {
		m.prefixDone = true
		m.prefix = nil
		return
	}
	if c != '\t' && c != '\n' {
		if len(m.prefix) <= metadataTokenLimit {
			m.prefix = append(m.prefix, c)
		}
		return
	}
	switch strings.ToLower(strings.TrimSpace(string(m.prefix))) {
	case "trace", "debug", "info", "warn", "warning", "error", "dpanic", "panic", "fatal":
		text := strings.TrimSpace(string(m.prefix))
		m.level = append(append(json.RawMessage{'"'}, text...), '"')
		m.prefixDone = true
	}
	m.prefix = nil
	m.prefixFields++
	if m.prefixFields == 2 || c == '\n' {
		m.prefixDone = true
	}
}
