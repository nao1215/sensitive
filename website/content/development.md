---
title: Development
description: How embargo finds and masks a value, how the command runs a program, and which tests guard each layer.
---

[CONTRIBUTING.md](CONTRIBUTING.md) has the workflow, and [AGENTS.md](AGENTS.md) the package boundaries and commands. Report a bug in an [issue](https://github.com/nao1215/embargo/issues), or [sponsor maintenance](https://github.com/sponsors/nao1215).

## How a value is found

![Structured values are walked with their keys; text is decoded once, only the detectors whose hint occurs run, and the findings are filtered, merged and masked](figures/detection-flow.svg)

A finding is a half-open byte span of the original input, with a kind and a confidence. Detectors in `internal/detect` parse and validate without regular expressions, and the root package owns the policy: which kinds run, the threshold, the sensitive keys and the replacement. The command reads lines in batches, scans them on every CPU and writes them in input order; a batch that starts inside a PEM block, a JSON document, a YAML block or a quoted CSV field is scanned again from the true state.

## How `embargo run` connects the pipes

![embargo run passes stdin and signals to the command, masks its stdout and stderr separately and exits with its status](figures/run-pipes.svg)

## How it is tested

![Six layers from examples and unit tests up to CI gates](figures/test-layers.svg)

The site is checked against the code too: every Go block here is a runnable Example or test, every command line runs in the E2E specs, the tables come from generators, and every link to a page or a repository file must exist. [doc/testing.md](doc/testing.md) has each technique, its commands and its measurements, and `doc/` keeps the other generated measurements and their data.

To change a detector, edit its constant comment in `finding.go` and its entry under [Rules by kind](/kinds/#rules-by-kind), then run `go -C tests run ./cmd/detectordocs` to regenerate the table on the Kinds page.
