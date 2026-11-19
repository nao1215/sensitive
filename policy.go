package embargo

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// fieldPolicy is the one place that decides how a structured value is masked.
// JSON documents, slog attributes and groups, and HTTP headers and queries are
// trees of keyed members; each sink walks its own tree in order and reports
// every member key here, so key masking, sensitive keys, detected key paths
// and name and value pairs follow one rule set whatever the sink. Scalars are
// masked by the embedded eventScanner with their member key as context.
// A policy holds only the path to the current member, so a walk needs memory
// for its depth rather than its size.
type fieldPolicy struct {
	scan eventScanner
	// path holds the entered members in storage borrowed from the scanner on
	// the first member and returned by release.
	path *scanScratch
	// prefix is a key path bound before the walk, such as slog WithGroup names.
	prefix string
	// top is a member entered at the root before path is borrowed; a flat
	// record never borrows path.
	top memberKey
	// prefixCrossed is set when a detected key path includes the prefix, so
	// the sink writes its bound groups as the marker.
	prefixCrossed bool
	// inTop reports that top is entered and not yet in path.
	inTop bool
}

// newFieldPolicy returns a policy for one walk; its owner calls release.
func newFieldPolicy(scanner *Scanner, prefix string) fieldPolicy {
	return fieldPolicy{scan: eventScanner{scanner: scanner, remaining: maxScanBytes}, path: nil, prefix: prefix, top: memberKey{}, prefixCrossed: false, inTop: false}
}

// release returns the path storage, which holds only keys without findings.
func (p *fieldPolicy) release() {
	if p.path != nil {
		p.scan.scanner.returnScratch(p.path)
		p.path = nil
	}
}

// memberKey is the decision for one member key.
type memberKey struct {
	// key is the decoded original key, the scan context of the member value.
	key string
	// masked is the key as written when no key path crosses it.
	masked string
	// sensitive reports a key whose whole value is written as the marker.
	sensitive bool
}

// changed reports whether the key text itself had findings.
func (k memberKey) changed() bool { return k.masked != k.key }

// member masks key, enters it and reports its decision; the sink calls leave
// after the member value.
func (p *fieldPolicy) member(ctx context.Context, key string) (memberKey, error) {
	result, err := p.scan.maskCached(ctx, key)
	if err != nil {
		return memberKey{}, err
	}
	decision := memberKey{key: key, masked: result.masked, sensitive: result.sensitive}
	return decision, p.enter(ctx, decision)
}

// cachedMember is member for a key lexeme that needs no decoding. ok is false
// when key is not cached; then nothing was entered or charged and the sink
// decodes the key and calls member.
func (p *fieldPolicy) cachedMember(ctx context.Context, key []byte) (memberKey, bool, error) {
	result, ok, err := cachedKey(ctx, &p.scan, key)
	if !ok || err != nil {
		return memberKey{}, false, err
	}
	decision := memberKey{key: result.key, masked: result.key, sensitive: result.sensitive}
	return decision, true, p.enter(ctx, decision)
}

// enter appends a key to the path. A key with findings is written masked and
// joins the path as the marker. A finding over the joined path that crosses
// the last join, such as user.email spelled over two keys, marks every
// entered key and any bound prefix to be written as the marker; detecting an
// ancestor alone does not hide its descendants.
func (p *fieldPolicy) enter(ctx context.Context, key memberKey) error {
	if p.path == nil && p.prefix == "" && !p.inTop {
		p.top, p.inTop = key, true
		return nil
	}
	segment := key.key
	if key.changed() {
		segment = redactionMarker
	}
	if p.path == nil {
		p.path = p.scan.scanner.takeScratch()
		p.path.keys = append(p.path.keys, p.prefix...)
		if p.inTop {
			p.path.members = append(p.path.members, pathMember{parent: 0, crossed: false})
			p.path.keys = append(p.path.keys, pathKey(p.top)...)
			p.inTop = false
		}
	}
	stack := p.path
	parent := len(stack.keys)
	stack.members = append(stack.members, pathMember{parent: parent, crossed: false})
	if parent == 0 || segment == "" {
		stack.keys = append(stack.keys, segment...)
		return nil
	}
	stack.keys = append(append(stack.keys, '.'), segment...)
	crossed, err := p.scan.joinedKeySensitive(ctx, stack.keys, parent)
	if err != nil || !crossed {
		return err
	}
	for i := range stack.members {
		stack.members[i].crossed = true
	}
	if p.prefix != "" {
		p.prefixCrossed = true
	}
	return nil
}

// leave ends the last entered member and reports whether its key is written
// as the marker because a detected key path crosses it.
func (p *fieldPolicy) leave() bool {
	if p.inTop {
		p.inTop = false
		return false
	}
	stack := p.path
	last := stack.members[len(stack.members)-1]
	stack.members = stack.members[:len(stack.members)-1]
	stack.keys = stack.keys[:last.parent]
	return last.crossed
}

// textMember decides a member whose value is text, such as a query parameter,
// and returns the key and value as written.
func (p *fieldPolicy) textMember(ctx context.Context, key, value string) (maskedKey, maskedValue string, err error) {
	decision, err := p.member(ctx, key)
	if err != nil {
		return "", "", err
	}
	maskedValue = redactionMarker
	if !decision.sensitive {
		if maskedValue, err = p.scan.maskScalar(ctx, value, key); err != nil {
			return "", "", err
		}
	}
	maskedKey = decision.masked
	if p.leave() {
		maskedKey = redactionMarker
	}
	return maskedKey, maskedValue, nil
}

// sensitive reports whether a value scanned with key as context is written
// whole as the marker.
func (p *fieldPolicy) sensitive(key string) bool {
	return key != "" && p.scan.scanner.cachedSensitiveKey(key)
}

// pathMember is one entered member: the path length before its key, and
// whether a detected key path crosses it, in which case the sink writes the
// marker for its key when it leaves the member.
type pathMember struct {
	parent  int
	crossed bool
}

// pathKey returns the key as it joins the path: the marker when its text had
// findings, as enter spells it.
func pathKey(key memberKey) string {
	if key.changed() {
		return redactionMarker
	}
	return key.key
}

// namedPair tracks one object that stores a setting as separate name and value
// members, as Kubernetes env, ECS task definitions, SSM parameters and
// CloudFormation parameters do: {"name":"DB_PASSWORD","value":"hunter2"}.
// Every value member is written as the marker when any name member is a
// sensitive key, in either member order and also when a member repeats: a
// non-empty text value, or a whole object or array as under a sensitive key.
// Numeric and boolean values, as in metric samples, stay visible.
// H identifies a value member in the sink's output.
type namedPair[H any] struct {
	first     H
	values    []H
	seen      bool
	sensitive bool
}

// valueShape is how a pair value member is written.
type valueShape uint8

const (
	// shapeOther is a number, boolean, null or empty text, which stays visible.
	shapeOther valueShape = iota
	// shapeText is a non-empty string.
	shapeText
	// shapeContainer is an object, array or group.
	shapeContainer
)

// name records a name member whose text is name.
func (n *namedPair[H]) name(p *fieldPolicy, name string) {
	if p.scan.scanner.cachedSensitiveKey(settingName(name)) {
		n.sensitive = true
	}
}

// value records a value member written with shape at handle.
func (n *namedPair[H]) value(shape valueShape, handle H) {
	if shape == shapeOther {
		return
	}
	if !n.seen {
		n.first, n.seen = handle, true
	} else {
		n.values = append(n.values, handle)
	}
}

// hidden calls hide for every value member to write as the marker.
func (n *namedPair[H]) hidden(hide func(H)) {
	if !n.sensitive || !n.seen {
		return
	}
	hide(n.first)
	for _, handle := range n.values {
		hide(handle)
	}
}

// jsonValueShape classifies an encoded JSON value as a pair value member.
func jsonValueShape(raw []byte) valueShape {
	if len(raw) == 0 {
		return shapeOther
	}
	if raw[0] == '{' || raw[0] == '[' {
		return shapeContainer
	}
	if raw[0] == '"' && len(raw) > len(`""`) {
		return shapeText
	}
	return shapeOther
}

// jsonName returns the text of an encoded JSON string, for a name member.
func jsonName(raw []byte) (string, bool) {
	var name string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &name) != nil {
		return "", false
	}
	return name, true
}

// pairField classifies a member of a name and value pair.
type pairField uint8

const (
	pairNone pairField = iota
	pairName
	pairValue
)

// namedValueField lowers a short member key and drops separators, as
// normalizeKey does, without allocating; longer keys are never pair members.
func namedValueField(key string) pairField {
	// Most keys are rejected by their first letter without folding.
	const starts = 1<<('k'-'a') | 1<<('n'-'a') | 1<<('o'-'a') | 1<<('p'-'a') | 1<<('v'-'a')
	if key == "" {
		return pairNone
	}
	if c := ascii.ToLower(key[0]); c >= 'a' && c <= 'z' && starts>>(c-'a')&1 == 0 {
		return pairNone
	}
	return foldedPairField(key)
}

// foldedPairField is namedValueField for a key that may name a pair member.
func foldedPairField(key string) pairField {
	var folded [len("parametervalue")]byte
	n := 0
	for i := range len(key) {
		c := key[i]
		if c == '_' || c == '-' || c == '.' || c == ' ' {
			continue
		}
		if n == len(folded) {
			return pairNone
		}
		folded[n] = ascii.ToLower(c)
		n++
	}
	switch string(folded[:n]) {
	case "name", "key", "parameterkey", "parametername", "optionname", "variable":
		return pairName
	case "value", "parametervalue":
		return pairValue
	}
	return pairNone
}

// settingName keeps the last segment of a parameter path such as
// /prod/db/password, so the key rule sees the setting rather than the path.
func settingName(name string) string {
	return name[strings.LastIndexByte(name, '/')+1:]
}

func joinedKey(groups, key string) string {
	if groups == "" {
		return key
	}
	if key == "" {
		return groups
	}
	return groups + "." + key
}
