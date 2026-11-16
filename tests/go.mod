module github.com/nao1215/embargo/tests

go 1.26.11

replace github.com/nao1215/embargo => ../

require (
	github.com/bytedance/godlp v1.2.15
	github.com/getsentry/sentry-go v0.50.0
	github.com/m-mizutani/masq v0.2.3
	github.com/nao1215/embargo v0.5.1
	github.com/rs/zerolog v1.35.1
	github.com/samber/slog-formatter v1.3.0
	github.com/showa-93/go-mask v0.6.2
	github.com/sirupsen/logrus v1.10.2
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/log v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/sdk/log v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.59.0
	golang.org/x/tools v0.52.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/nao1215/embargo/adapters/logrus v0.5.0
	github.com/nao1215/embargo/adapters/zap v0.5.1
	github.com/nao1215/embargo/adapters/zerolog v0.5.0
	github.com/samber/lo v1.53.0 // indirect
	github.com/samber/slog-common v0.21.0 // indirect
	github.com/samber/slog-multi v1.8.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/nao1215/embargo/adapters/zap => ../adapters/zap

replace github.com/nao1215/embargo/adapters/logrus => ../adapters/logrus

replace github.com/nao1215/embargo/adapters/zerolog => ../adapters/zerolog
