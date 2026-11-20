// Command embargo masks secrets and personal data in log lines read from files
// or stdin and writes them to stdout; --format json and --format jsonl report
// finding counts and locations instead, without echoing input. embargo run
// starts a command and masks its stdout and stderr the same way.
package main
