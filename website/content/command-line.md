---
title: Command line
description: Mask a log or the output of a program with the embargo command, count findings, and gate CI.
toc: true
---

The `embargo` command is part of the root module. It imports only embargo and the standard library and sends nothing over the network. [Install](/install/#command) it with `go install` or from a release.

| Where | Command |
|---|---|
| An application that prints secrets | `embargo run ./app >> app.log` |
| Logs shared in an issue or a chat | `kubectl logs deploy/api \| embargo > share.log` |
| A live log before it is shipped | `tail -f app.log \| embargo \| your-shipper` |
| A CI gate on a saved log | `out=$(embargo --format jsonl app.log) && test -z "$out"` |

## Mask a log

The command reads the named files in order, or stdin, and writes every line masked to stdout.

```sh
kubectl logs deploy/api | embargo > masked.log
embargo --kinds pan,credential app.log
```

- A line that holds one JSON object or array keeps its keys, types and nesting, and is written compact. Other lines, and JSON over 1 MiB, are masked as text.
- Line endings are kept, including CRLF and a missing final newline. Output is flushed whenever no more input is waiting, so `tail -f app.log | embargo` shows each line as it arrives.
- gzip and bzip2 input, such as `app.log.1.gz`, is decompressed. zstd, xz, zip, 7z and lz4 stop with an error, since no detector reads compressed bytes.
- `--input csv` and `--input tsv` read the first line as column names, which work as keys for every field below them: a `password` column is masked although its values look like any text. Files that all end in `.csv` or `.tsv`, optionally followed by `.gz` or `.bz2`, are read this way by default; `--input lines` turns that off.
- A value whose key is on an earlier line is masked when the key is sensitive: the value after `"token":` in pretty-printed JSON, an array or object under a sensitive key, a YAML block scalar (`password: |`) or list, and a CEF `cs1=` field whose `cs1Label=` names a sensitive key.
- Lines are scanned on every CPU in batches and written in input order.
- A UTF-8 byte order mark is kept. Input that starts with a UTF-16 byte order mark, which Windows PowerShell 5 writes for `>`, stops with an error instead of passing through unmasked.

`--kinds` takes `all` or a comma-separated list, and `--min-confidence` a number from 0 to 1. Flags come before the files, `-` reads stdin, and `--` ends the flags. A flag error names the flag and its allowed values and never repeats what was passed. A read error or a line over 4 MiB stops the output before that line, with a message that names only the line number.

## Run a command

`embargo run COMMAND [arg ...]` starts the command with embargo's stdin, masks its stdout onto stdout and its stderr onto stderr, and exits with the command's status. Flags go before `run`.

```sh
embargo run sh app.sh >> app.log
embargo --kinds all run sh app.sh
```

A command ended by a signal exits with 128 plus the signal number, as in a shell. SIGTERM and SIGHUP sent to embargo are passed on, and Ctrl-C reaches the command from the terminal. A child process that keeps the output open after the command exits keeps embargo running, as it would keep a shell pipe open.

## Count findings

`--format json` counts findings per kind instead of writing the log. Run it on a local log before choosing kinds; it counts findings, not confirmed secrets.

```sh
embargo --format json < app.log
embargo --format json --kinds all app.log
embargo --format json --kinds pan,credential --min-confidence 0.7 app.log
```

`--samples` sets how many locations per kind the report lists (default 3, 0 to 20); the counts always cover the whole input. A location has zero-based byte offsets `start` and `end`, a one-based `line` and a zero-based byte `column`, so `card=4111111111111111` gives start 5, end 21, line 1, column 5. Each kind has a `drop_option` that shows how to leave it out. No format prints a matched value or the text around it.

The report scans each line on its own, so it does not apply the sensitive keys to JSON values the way the filter does.

## List every finding and gate CI

`--format jsonl` prints one JSON object per finding as each line is read, with no sample limit, so a script or an agent can visit every location. A clean log prints nothing, so a CI step can fail on any output:

```sh
embargo --format jsonl app.log
out=$(embargo --format jsonl app.log) && test -z "$out"
```

| Exit status | Meaning |
|---|---|
| 0 | The input was read in full, findings or not |
| 1 | An input, output or masking error |
| 2 | Invalid flags or operands |
| 126, 127 | `run` could not start the command, or did not find it |
| 141 | The reader closed the output, as `head` does; nothing is printed |
| other | `run` passes on the command's status |

The CI line fails on both a finding and an error. `! embargo --format jsonl app.log | grep -q .` would pass when embargo cannot read the file, because the error prints nothing.

## Compare settings

Run `--format json` once per setting on the same file and diff the reports. The counts are complete and the samples hold no log text, so the diff shows which kinds a selection or threshold gains or loses.

```sh
embargo --format json --kinds pan,email app.log > before.json
embargo --format json --kinds pan,credential --min-confidence 0.7 app.log > after.json
diff before.json after.json
```

[Kinds](/kinds/#confidence-and-thresholds) explains what a threshold drops along with the noise.
