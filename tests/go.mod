module github.com/nao1215/embargo/tests

go 1.26.11

replace github.com/nao1215/embargo => ../

require (
	github.com/bytedance/godlp v1.2.15
	github.com/getsentry/sentry-go v0.50.0
	github.com/m-mizutani/masq v0.2.3
	github.com/nao1215/embargo v0.17.0
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

require github.com/icntswm/go-masker v0.6.1

require (
	connectrpc.com/connect v1.21.1
	github.com/awslabs/ferret-scan/v2 v2.4.3
	github.com/ggwhite/go-masker/v3 v3.3.0
	github.com/gin-gonic/gin v1.12.0
	github.com/labstack/echo/v5 v5.4.6
	github.com/pii-shield/pii-shield/v3 v3.0.0
)

require (
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/hhrutter/tiff v1.0.6 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/ledongthuc/pdf v0.0.0-20250511090121-5959a4027728 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-runewidth v0.0.27 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pdfcpu/pdfcpu v0.15.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	github.com/richardlehane/mscfb v1.0.8 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/rwcarlsen/goexif v0.0.0-20190401172101-9e8deecbddbd // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/image v0.45.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/nao1215/embargo/adapters/logrus v0.16.1
	github.com/nao1215/embargo/adapters/otel v0.16.1
	github.com/nao1215/embargo/adapters/sentry v0.16.1
	github.com/nao1215/embargo/adapters/zap v0.16.1
	github.com/nao1215/embargo/adapters/zerolog v0.16.1
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

replace github.com/nao1215/embargo/adapters/otel => ../adapters/otel

replace github.com/nao1215/embargo/adapters/sentry => ../adapters/sentry
