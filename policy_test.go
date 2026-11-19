package embargo

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/saferecord"
)

func TestFieldPolicyPath(t *testing.T) {
	t.Parallel()
	// The fixture reports user.email spelled over two keys, so only a path
	// that joins them crosses a join.
	scanner := NewScanner(WithKinds(), WithoutDefaultSensitiveKeys(), WithDetector(pathDetector{}))
	policy := newFieldPolicy(scanner, "")
	defer policy.release()
	enter := func(key string) memberKey {
		t.Helper()
		decision, err := policy.member(t.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}
	enter("request")
	enter(pathUser)
	enter(pathEmail)
	if path := policyPath(&policy); path != "request.user.email" {
		t.Fatalf("path = %q", path)
	}
	for _, key := range []string{pathEmail, pathUser, "request"} {
		if !policy.leave() {
			t.Fatalf("%s left without the marker", key)
		}
	}
	enter(pathUser)
	enter("name")
	first, second := policy.leave(), policy.leave()
	if first || second || policyPath(&policy) != "" || policyDepth(&policy) != 0 {
		t.Fatal("an unrelated path was marked or not unwound")
	}
	if policy.prefixCrossed {
		t.Fatal("a policy without a prefix reported a crossed prefix")
	}
}

func TestFieldPolicyPrefix(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(), WithoutDefaultSensitiveKeys(), WithDetector(pathDetector{}))
	for _, tc := range []struct {
		prefix, key string
		crossed     bool
	}{
		{pathUser, pathEmail, true},
		{"request.user", pathEmail, true},
		{pathUser, "name", false},
		{"", pathEmail, false},
	} {
		policy := newFieldPolicy(scanner, tc.prefix)
		if _, err := policy.member(t.Context(), tc.key); err != nil {
			t.Fatal(err)
		}
		if crossed := policy.leave(); crossed != tc.crossed || policy.prefixCrossed != (tc.crossed && tc.prefix != "") {
			t.Errorf("%s.%s: crossed %v, prefix crossed %v", tc.prefix, tc.key, crossed, policy.prefixCrossed)
		}
		policy.release()
		if policy.path != nil {
			t.Fatal("release kept the path storage")
		}
	}
}

func TestFieldPolicyMemberKeys(t *testing.T) {
	t.Parallel()
	policy := newFieldPolicy(NewScanner(), "")
	defer policy.release()
	decision, err := policy.member(t.Context(), documentedEmail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.changed() || decision.masked != redactionMarker || pathKey(decision) != redactionMarker || decision.key != documentedEmail {
		t.Fatalf("detected key decision = %+v", decision)
	}
	if path := policyPath(&policy); path != redactionMarker {
		t.Fatalf("a detected key joined the path as %q", path)
	}
	policy.leave()
	decision, err = policy.member(t.Context(), credentialFixtureKey)
	if err != nil || !decision.sensitive || decision.changed() || pathKey(decision) != credentialFixtureKey {
		t.Fatalf("sensitive key decision = %+v, %v", decision, err)
	}
	policy.leave()
	if !policy.sensitive(credentialFixtureKey) || policy.sensitive("") || policy.sensitive(statusKey) {
		t.Fatal("sensitive key rule changed")
	}
	// A cached key needs no decoding and returns the same decision.
	if _, err = policy.member(t.Context(), statusKey); err != nil {
		t.Fatal(err)
	}
	policy.leave()
	cached, ok, err := policy.cachedMember(t.Context(), []byte(statusKey))
	if err != nil || !ok || cached.key != statusKey || cached.changed() || cached.sensitive {
		t.Fatalf("cached member = %+v, %v, %v", cached, ok, err)
	}
	policy.leave()
	if _, ok, err := policy.cachedMember(t.Context(), []byte("never-seen-key")); ok || err != nil || policyDepth(&policy) != 0 {
		t.Fatal("an uncached key was entered")
	}
}

func TestFieldPolicyTextMember(t *testing.T) {
	t.Parallel()
	policy := newFieldPolicy(NewScanner(), "")
	defer policy.release()
	for _, tc := range []struct{ key, value, wantKey, wantValue string }{
		{tokenKey, "opaque", tokenKey, redactionMarker},
		{"note", "mail " + documentedEmail, "note", "mail " + redactionMarker},
		{documentedEmail, budgetPublicKey, redactionMarker, budgetPublicKey},
		{statusKey, "ok", statusKey, "ok"},
	} {
		key, value, err := policy.textMember(t.Context(), tc.key, tc.value)
		if err != nil || key != tc.wantKey || value != tc.wantValue {
			t.Errorf("textMember(%q, %q) = %q, %q, %v", tc.key, tc.value, key, value, err)
		}
	}
	if policyDepth(&policy) != 0 || policy.path != nil {
		t.Fatal("textMember left members entered or borrowed path storage")
	}
	policy.scan.remaining = 0
	if _, _, err := policy.textMember(t.Context(), "note", "value"); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("textMember ignored the budget")
	}
}

func TestFieldPolicyCrossedTextMember(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(), WithoutDefaultSensitiveKeys(), WithDetector(pathDetector{}))
	policy := newFieldPolicy(scanner, pathUser)
	defer policy.release()
	key, value, err := policy.textMember(t.Context(), pathEmail, budgetPublicKey)
	if err != nil || key != redactionMarker || value != budgetPublicKey || !policy.prefixCrossed {
		t.Fatalf("crossed text member = %q, %q, %v", key, value, err)
	}
	policy.scan.remaining = len(pathEmail) - 1
	if _, _, err := policy.textMember(t.Context(), pathEmail, budgetPublicKey); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("key budget ignored")
	}
}

func TestNamedPair(t *testing.T) {
	t.Parallel()
	policy := newFieldPolicy(NewScanner(), "")
	collect := func(pair *namedPair[int]) []int {
		var hidden []int
		pair.hidden(func(i int) { hidden = append(hidden, i) })
		return hidden
	}
	var pair namedPair[int]
	pair.value(shapeText, 1)
	pair.value(shapeOther, 2)
	pair.value(shapeContainer, 3)
	if got := collect(&pair); got != nil {
		t.Fatalf("values hidden without a sensitive name: %v", got)
	}
	pair.name(&policy, "PORT")
	if got := collect(&pair); got != nil {
		t.Fatalf("a public name hid values: %v", got)
	}
	pair.name(&policy, "/prod/db/password")
	if got := collect(&pair); !slices.Equal(got, []int{1, 3}) {
		t.Fatalf("hidden = %v, want every text and container value", got)
	}
	var empty namedPair[int]
	empty.name(&policy, credentialFixtureKey)
	if got := collect(&empty); got != nil {
		t.Fatalf("a pair without values hid %v", got)
	}
}

func TestValueShapes(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]valueShape{
		`""`: shapeOther, `"x"`: shapeText, `{}`: shapeContainer, `[]`: shapeContainer,
		`12`: shapeOther, `false`: shapeOther, jsonNull: shapeOther, ``: shapeOther,
	} {
		if got := jsonValueShape([]byte(raw)); got != want {
			t.Errorf("jsonValueShape(%s) = %d, want %d", raw, got, want)
		}
	}
	for _, tc := range []struct {
		value slog.Value
		want  valueShape
	}{
		{slog.StringValue(""), shapeOther},
		{slog.StringValue("x"), shapeText},
		{slog.GroupValue(slog.Int("n", 1)), shapeContainer},
		{slog.AnyValue(maskedJSON(`{"a":1}`)), shapeContainer},
		{slog.AnyValue(maskedJSON(`"x"`)), shapeText},
		{slog.AnyValue(maskedJSON(`1`)), shapeOther},
		{slog.AnyValue([]int{1}), shapeOther},
		{slog.IntValue(7), shapeOther},
	} {
		if got := slogShape(tc.value); got != tc.want {
			t.Errorf("slogShape(%v) = %d, want %d", tc.value, got, tc.want)
		}
	}
	for raw, want := range map[string]bool{`"name"`: true, `"n\u0061me"`: true, `1`: false, ``: false, `"bad`: false} {
		name, ok := jsonName([]byte(raw))
		if ok != want || (ok && name != "name") {
			t.Errorf("jsonName(%s) = %q, %v", raw, name, ok)
		}
	}
	if settingName("/prod/db/"+credentialFixtureKey) != credentialFixtureKey || settingName(credentialFixtureKey) != credentialFixtureKey || settingName("dir/") != "" {
		t.Fatal("setting name changed")
	}
	if joinedKey("", "a") != "a" || joinedKey("a", "") != "a" || joinedKey("a", "b") != "a.b" {
		t.Fatal("joined key changed")
	}
}

const (
	pathUser  = "user"
	pathEmail = "email"
)

// pathDetector reports user.email wherever the text spells it.
type pathDetector struct{}

func (pathDetector) Scan(data []byte) []Finding {
	var findings []Finding
	const target = "user.email"
	for i := 0; i+len(target) <= len(data); i++ {
		if string(data[i:i+len(target)]) == target {
			findings = append(findings, Finding{Kind: "path", Start: i, End: i + len(target), Confidence: 1})
		}
	}
	return findings
}

func TestJSONWalkerTokenFailures(t *testing.T) {
	t.Parallel()
	// The public entry points validate a document first, so these tokens reach
	// the walker only through a direct call.
	invalid := []byte(`"\x"`)
	walker := jsonWalker{policy: newFieldPolicy(NewScanner(), "")}
	if err := walker.stringValue(t.Context(), invalid, ""); !errors.Is(err, saferecord.ErrMasking) {
		t.Fatalf("invalid string token: %v", err)
	}
	if _, err := walker.objectKey(t.Context(), invalid); !errors.Is(err, saferecord.ErrMasking) {
		t.Fatalf("invalid key token: %v", err)
	}
	walker.policy.scan.remaining = 0
	if err := walker.stringValue(t.Context(), []byte(`"a\u0062"`), ""); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatalf("escaped string past the budget: %v", err)
	}
}

func TestOversizedGroupNameIsWithheld(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&out, nil), NewScanner())).WithGroup(strings.Repeat("g", maxScanBytes+1))
	logger.Info("event", statusKey, "ok")
	if !strings.Contains(out.String(), "embargo: record withheld (size limit)") || strings.Contains(out.String(), "ggg") {
		t.Fatalf("oversized group name: %.200s", out.String())
	}
}

func TestJoinedPathCache(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	scan := eventScanner{scanner: scanner, remaining: maxScanBytes}
	for range 2 {
		before := scan.remaining
		if crossed, err := scan.joinedKeySensitive(t.Context(), []byte("request.user"), len("request")); err != nil || crossed {
			t.Fatal("clean path crossed")
		}
		if before-scan.remaining != len("request.user") {
			t.Fatal("a cached path did not pay its budget")
		}
	}
	if scanner.paths.size() != 1 {
		t.Fatalf("clean path cached %d times", scanner.paths.size())
	}
	// A path with a finding is scanned every time and never cached.
	for range 2 {
		if crossed, err := scan.joinedKeySensitive(t.Context(), []byte("alice@example.com"), len("alice@example")); err != nil || !crossed {
			t.Fatal("detected path did not cross")
		}
	}
	if scanner.paths.size() != 1 {
		t.Fatal("a path with findings was cached")
	}
	// Paths up to the key cache's length limit are cached, longer ones not.
	for _, n := range []int{maxCachedKeyBytes, maxCachedKeyBytes + 1} {
		path := []byte(strings.Repeat("a", n-len(".b")) + ".b")
		if _, err := scan.joinedKeySensitive(t.Context(), path, n-len(".b")); err != nil {
			t.Fatal(err)
		}
		if cached := scanner.paths.loadBytes(path) != nil; cached != (n <= maxCachedKeyBytes) {
			t.Errorf("path of %d bytes cached = %v", n, cached)
		}
	}
}

func TestSlogPairsHideValues(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}), NewScanner()))
	logger.Info("m", slog.Group("env", "other", "kept", "name", "DB_PASSWORD", "value", "hunter2"), "name", 7, "value", "visible")
	want := `{"level":"INFO","msg":"m","env":{"other":"kept","name":"DB_PASSWORD","value":"[REDACTED]"},"name":7,"value":"visible"}`
	if got := strings.TrimSpace(out.String()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestPooledScratchLimits(t *testing.T) {
	t.Parallel()
	scanner := NewScanner()
	for _, tc := range []struct {
		keys, members int
		pooled        bool
	}{
		{largestPooledBuffer, maxPooledMembers, true},
		{largestPooledBuffer + 1, 0, false},
		{0, maxPooledMembers + 1, false},
	} {
		scratch := &scanScratch{text: nil, findings: nil, keys: make([]byte, tc.keys), members: make([]pathMember, tc.members)}
		scanner.returnScratch(scratch)
		// Pooled storage is truncated for its next user; dropped storage is not.
		if pooled := len(scratch.keys) == 0 && len(scratch.members) == 0; pooled != tc.pooled {
			t.Errorf("keys %d members %d: pooled %v", tc.keys, tc.members, pooled)
		}
	}
}

// policyPath returns the entered key path, whether or not storage is borrowed.
func policyPath(p *fieldPolicy) string {
	if p.inTop {
		return pathKey(p.top)
	}
	if p.path == nil {
		return ""
	}
	return string(p.path.keys)
}

// policyDepth returns the number of entered members.
func policyDepth(p *fieldPolicy) int {
	depth := 0
	if p.inTop {
		depth++
	}
	if p.path != nil {
		depth += len(p.path.members)
	}
	return depth
}
