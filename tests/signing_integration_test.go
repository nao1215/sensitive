package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

// observationTB catches intentional failures without weakening the detector.
// failure is a code and message the application defines for a failure, as a
// service would log instead of the raw error.
type failure struct{ code, message string }

func signingFailed() failure { return failure{code: "signing_failed", message: "Signing failed"} }
func withheld() failure      { return failure{code: "error", message: "Error details withheld"} }

func (f failure) fields() map[string]string {
	return map[string]string{"code": f.code, "message": f.message}
}

type observationTB struct {
	testing.TB

	cleanup  []func()
	messages []string
	errors   int
}

func (t *observationTB) Error(args ...any) {
	t.errors++
	t.messages = append(t.messages, fmt.Sprint(args...))
}
func (t *observationTB) Cleanup(f func()) { t.cleanup = append(t.cleanup, f) }
func (t *observationTB) finish() {
	for _, v := range slices.Backward(t.cleanup) {
		v()
	}
}

func TestSigningAcceptance(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Independent acceptance scenarios keep their literal expected results local.
	for _, mode := range []string{"safe", "leak", "missing", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			reported := failure{"signing_unavailable", "Signing is temporarily unavailable"}
			r.ExpectJSON("logs", []string{"failure"}, reported.fields(), 1)
			r.Expect("response", func(b []byte) bool { return bytes.Equal(b, []byte("503 signing_unavailable")) })
			var request struct {
				Seed embargo.Input[string] `json:"seed"`
			}
			input, err := json.Marshal(map[string]string{"seed": string(r.Canary())})
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal("input decode failed")
			}
			key := request.Seed.Secret()
			raw := &url.Error{Op: "sign", URL: "https://signer.invalid/?seed=" + key.Reveal(), Err: errors.New("offline")}
			logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))
			logged := reported
			if mode == "regressed" {
				logged = withheld()
			}
			if mode != "missing" {
				logger.Error("signing request failed", "operation", "sign", "key", key,
					"failure", slog.GroupValue(slog.String("code", logged.code), slog.String("message", logged.message)))
				if _, err := r.Writer("response").Write([]byte("503 signing_unavailable")); err != nil {
					t.Fatal("write failed")
				}
			}
			if mode == "leak" {
				logger.Error("transport failed", "error", raw)
			}
			passed := r.Check()
			probe.finish()
			if passed != (mode == "safe") || (probe.errors == 0) != (mode == "safe") {
				t.Fatal("acceptance detector returned the wrong verdict")
			}
		})
	}
}

func TestSigningKeyRepresentations(t *testing.T) {
	t.Parallel()
	for _, leak := range []bool{false, true} {
		probe := &observationTB{TB: t}
		r := embargotest.New(probe)
		rawKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), r.Canary())
		if err != nil {
			t.Fatal("fake key fixture invalid")
		}
		key := embargo.NewSecret(rawKey)
		digest := sha256.Sum256([]byte("public transaction fixture"))
		signature, err := ecdsa.SignASN1(rand.Reader, key.Reveal(), digest[:])
		if err != nil || !ecdsa.VerifyASN1(&key.Reveal().PublicKey, digest[:], signature) {
			t.Fatal("signing fixture failed")
		}
		r.Expect("logs", func(data []byte) bool { return bytes.Contains(data, []byte("signing completed")) })
		logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))
		if leak {
			logger.Info("signing completed", "key", key.Reveal())
		} else {
			logger.Info("signing completed", "key", key, "seed", embargo.NewSecret([32]byte(r.Canary())))
		}
		if r.Check() == leak {
			t.Fatal("signing key detector returned wrong verdict")
		}
		probe.finish()
	}
}
