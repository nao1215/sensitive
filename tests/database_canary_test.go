package tests

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

// A connector avoids registering a global SQL driver and supplies a real Rows
// path with a plain string. The application's domain model imports no wrapper.
type canaryConnector struct{ value string }

func (c canaryConnector) Connect(context.Context) (driver.Conn, error) {
	return &canaryConnection{value: c.value}, nil
}
func (canaryConnector) Driver() driver.Driver { return canaryDriver{} }

type canaryDriver struct{}

func (canaryDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type canaryConnection struct{ value string }

func (c *canaryConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &canaryRows{value: c.value}, nil
}

func (*canaryConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unavailable")
}

func (*canaryConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transaction unavailable")
}
func (*canaryConnection) Close() error { return nil }

type canaryRows struct {
	value string
	done  bool
}

func (*canaryRows) Columns() []string { return []string{comparisonPasswordKey} }
func (*canaryRows) Close() error      { return nil }
func (r *canaryRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	values[0] = r.value
	r.done = true
	return nil
}

//nolint:goconst // The fixture explicitly asserts the public redaction marker.
func TestDatabaseCanaryInjection(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
	db := sql.OpenDB(canaryConnector{value: string(r.Canary())})
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	var password string
	if err := db.QueryRowContext(t.Context(), "select password from config").Scan(&password); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(r.Writer("db/log"), nil), embargo.NewScanner()))
	logger.Info("loaded", slog.String(comparisonPasswordKey, password))
	r.ExpectJSON("db/log", nil, map[string]string{comparisonPasswordKey: "[REDACTED]"}, 1)
	r.Check()
}
