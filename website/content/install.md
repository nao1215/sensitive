---
title: Install
description: Install the embargo library, its logger adapters and the embargo command.
---

## Library

Go 1.26.11 or later. The root module has no requirements outside the standard library, and `embargotest` is part of it.

```sh
go get github.com/nao1215/embargo@v0.20.0
```

## Logger and SDK adapters

Each adapter is its own module, so an application downloads only the SDK it uses. Install the one for your logger or SDK:

```sh
go get github.com/nao1215/embargo/adapters/zap@v0.20.0
go get github.com/nao1215/embargo/adapters/zerolog@v0.20.0
go get github.com/nao1215/embargo/adapters/logrus@v0.20.0
go get github.com/nao1215/embargo/adapters/grpc@v0.20.0
go get github.com/nao1215/embargo/adapters/otel@v0.20.0
go get github.com/nao1215/embargo/adapters/sentry@v0.20.0
```

Adapter tags have the form `adapters/<name>/vX.Y.Z`, and each one requires the root release of the same version. Upgrade the root and every adapter together. The HTTP access log handler is in the root module and needs no adapter.

## Command

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.20.0
```

[Releases](https://github.com/nao1215/embargo/releases) also have archives for Linux, macOS and Windows on amd64 and arm64, and deb, rpm and apk packages for Linux. `checksums.txt` is signed with cosign, each archive has an SBOM, and each archive carries GitHub build provenance:

```sh
gh attestation verify embargo_0.20.0_linux_amd64.tar.gz --repo nao1215/embargo
```

The SLSA provenance in `multiple.intoto.jsonl` verifies with `slsa-verifier verify-artifact --provenance-path multiple.intoto.jsonl --source-uri github.com/nao1215/embargo --source-tag v0.20.0 <archive>`.
