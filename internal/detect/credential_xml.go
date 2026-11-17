package detect

import (
	"bytes"

	"github.com/nao1215/embargo/internal/ascii"
)

// xmlElementCredentials finds text content of XML elements whose local name is
// a credential key, such as <password>value</password> in SOAP payloads or
// <ns:Token> with a namespace prefix. Attributes on the opening tag are
// allowed; the content must be followed by the matching closing tag, and
// surrounding whitespace stays visible.
func (d *Credential) xmlElementCredentials(data []byte) []Finding {
	var out []Finding
	for i := bytes.IndexByte(data, '<'); i >= 0 && i < len(data); {
		next := i + 1
		if start, end, ok := d.xmlElementValue(data, i); ok {
			out = append(out, credentialFinding(start, end))
			next = end
		}
		at := bytes.IndexByte(data[next:], '<')
		if at < 0 {
			break
		}
		i = next + at
	}
	return out
}

func (d *Credential) xmlElementValue(data []byte, open int) (start, end int, ok bool) {
	name, tagEnd, ok := xmlOpenTag(data, open)
	if !ok {
		return 0, 0, false
	}
	local := name
	if colon := bytes.LastIndexByte(name, ':'); colon >= 0 {
		local = name[colon+1:]
	}
	if !d.secretKey(local) {
		return 0, 0, false
	}
	return xmlTextContent(data, name, tagEnd+1)
}

// xmlOpenTag parses a non-empty opening tag at open and returns its name and
// the position of its closing '>'.
func xmlOpenTag(data []byte, open int) (name []byte, tagEnd int, ok bool) {
	nameEnd := open + 1
	for nameEnd < len(data) && isXMLNameByte(data[nameEnd]) {
		nameEnd++
	}
	name = data[open+1 : nameEnd]
	if len(name) == 0 || !ascii.IsAlpha(name[0]) || nameEnd == len(data) || (data[nameEnd] != '>' && !isXMLSpace(data[nameEnd])) {
		return nil, 0, false
	}
	tagEnd = bytes.IndexByte(data[nameEnd:], '>')
	if tagEnd < 0 {
		return nil, 0, false
	}
	tagEnd += nameEnd
	if data[tagEnd-1] == '/' || bytes.IndexByte(data[nameEnd:tagEnd], '<') >= 0 {
		return nil, 0, false
	}
	return name, tagEnd, true
}

// xmlTextContent returns the trimmed text from content up to the matching
// closing tag of name, rejecting nested elements and reserved markers.
func xmlTextContent(data, name []byte, content int) (start, end int, ok bool) {
	contentEnd := bytes.IndexByte(data[content:], '<')
	if contentEnd < 0 {
		return 0, 0, false
	}
	contentEnd += content
	if !hasASCIIPrefix(data, contentEnd, "</") || !bytes.HasPrefix(data[contentEnd+len("</"):], name) || !hasASCIIPrefix(data, contentEnd+len("</")+len(name), ">") {
		return 0, 0, false
	}
	start, end = content, contentEnd
	for start < end && isXMLSpace(data[start]) {
		start++
	}
	for end > start && isXMLSpace(data[end-1]) {
		end--
	}
	if start == end || redactedCredentialValue(data[start:end]) {
		return 0, 0, false
	}
	return start, end, true
}

func isXMLNameByte(b byte) bool {
	return ascii.IsAlphaNum(b) || b == '_' || b == '-' || b == '.' || b == ':'
}

func isXMLSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
