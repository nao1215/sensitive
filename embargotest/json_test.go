package embargotest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func signingFields() map[string]string {
	return map[string]string{"code": "signing_failed", "message": "Signing failed"}
}

func TestExpectJSON(t *testing.T) {
	t.Parallel()
	good := `{"diagnostic":{"code":"signing_failed","message":"Signing failed"}}`
	cases := []struct {
		data  string
		path  []string
		count int
		valid bool
	}{
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		{data: good, path: []string{"diagnostic"}, count: 1, valid: true},
		{data: good + "\n{", path: []string{"diagnostic"}, count: 1, valid: false},
		{data: good + "\n[", path: []string{"diagnostic"}, count: 1, valid: false},
		{data: good + "\n" + good, path: []string{"diagnostic"}, count: 2, valid: true},
		{data: good, path: []string{"diagnostic"}, count: 2, valid: false},
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		{data: good, path: []string{"missing"}, count: 1, valid: false},
		{data: good, path: nil, count: 1, valid: false},
		{data: good, path: []string{"diagnostic"}, count: 0, valid: false},
		{data: "", path: nil, count: 1, valid: false},
		{data: "", path: nil, count: 0, valid: false},
		{data: `{}`, path: nil, count: 0, valid: false},
		{data: "{", path: nil, count: 1, valid: false},
		{data: `{"code":"signing_failed","code":"signing_failed","message":"Signing failed"}`, path: nil, count: 1, valid: false},
		{data: `{"code":"signing_failed","message":"Signing failed","other":[{"a":1,"a":2}]}`, path: nil, count: 1, valid: false},
		{data: `{"code":"signing_failed","message":"Signing failed","other":[1,true,null,{"a":2}]}`, path: nil, count: 1, valid: true},
		{data: `{"code":"signing_failed","message":"Signing failed"} trailing`, path: nil, count: 1, valid: false},
		{data: strings.Repeat("[", 66) + strings.Repeat("]", 66), path: nil, count: 1, valid: false},
		{data: `[{"code":"signing_failed","message":"Signing failed"}]`, path: []string{"diagnostic"}, count: 1, valid: false},
		{data: `{"code":"signing_failed"}`, path: nil, count: 1, valid: false},
		{data: `{"code":"signing_failed","message":7}`, path: nil, count: 1, valid: false},
		{data: `{"code":"signing_failed","message":"Signing failed","extra":"kept"}`, path: nil, count: 1, valid: true},
	}
	for _, tc := range cases {
		p := &probeTB{TB: t}
		r := New(p)
		write(t, r, "out", []byte(tc.data))
		r.ExpectJSON("out", tc.path, signingFields(), tc.count)
		if r.Check() != tc.valid {
			t.Fatalf("verdict mismatch for %q", tc.data)
		}
		p.finish()
	}
}

func TestExpectJSONEmptyFields(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	write(t, r, "out", []byte(`{"code":"signing_failed"}`))
	fields := map[string]string{"code": "signing_failed"}
	r.ExpectJSON("out", nil, map[string]string{}, 1)
	if r.Check() {
		t.Fatal("empty fields accepted")
	}
	p.finish()
	// The expectation keeps a copy: changing the caller's map has no effect.
	p = &probeTB{TB: t}
	r = New(p)
	write(t, r, "out", []byte(`{"code":"signing_failed"}`))
	r.ExpectJSON("out", nil, fields, 1)
	fields["code"] = "other"
	if !r.Check() {
		t.Fatal("caller map change affected the expectation")
	}
	p.finish()
}

func TestJSONDepthBoundary(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"array", "object"} {
		for _, depth := range []int{63, 64, 65, 66} {
			open, end := "[", "]"
			if kind == "object" {
				open, end = `{"x":`, "}"
			}
			nested := strings.Repeat(open, depth) + "0" + strings.Repeat(end, depth)
			data := `{"code":"signing_failed","message":"Signing failed","nested":` + nested + `}`
			p := &probeTB{TB: t}
			r := New(p)
			write(t, r, "out", []byte(data))
			r.ExpectJSON("out", nil, signingFields(), 1)
			if r.Check() != (depth <= 63) {
				t.Fatal("JSON depth boundary changed")
			}
			p.finish()
		}
	}
}

func TestJSONErrorPaths(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"private":1,"private":2}`, `{1:2}`, `{"bad`, `{"a":1]`, `[1}`, strings.Repeat("[", 66) + strings.Repeat("]", 66)} {
		_, err := jsonValue(json.NewDecoder(strings.NewReader(input)), 0)
		if err == nil {
			t.Fatalf("invalid input accepted: %q", input)
		}
		var malformed jsonError
		if errors.As(err, &malformed) && err.Error() != "embargotest: invalid JSON record" {
			t.Fatal("JSON error exposes input or changed")
		}
	}
}
