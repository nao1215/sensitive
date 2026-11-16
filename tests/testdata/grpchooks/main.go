// Command grpchooks exercises access-log metadata using caller-provided synthetic cases.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/nao1215/embargo"
	embargogrpc "github.com/nao1215/embargo/adapters/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func main() {
	if err := run(); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run() error {
	var rows [][]string
	if err := json.NewDecoder(os.Stdin).Decode(&rows); err != nil {
		return errors.New("invalid synthetic input")
	}
	if len(rows) == 0 {
		return errors.New("no cases exercised")
	}
	for i, row := range rows {
		if len(row) != 4 {
			return errors.New("invalid synthetic case")
		}
		if err := check(row[0], row[1], row[2], row[3]); err != nil {
			return fmt.Errorf("case %d: %w", i, err)
		}
	}
	_, err := fmt.Fprintf(os.Stdout, "checked %d unary and %d stream cases\n", len(rows), len(rows))
	return err
}

func check(text, needle, key, value string) error {
	scanner := embargo.NewScanner()
	var out bytes.Buffer
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(strings.ToLower(key), value, "detail", text))
	unary := embargogrpc.NewUnaryServerInterceptor(slog.New(slog.NewJSONHandler(&out, nil)), scanner)
	response, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/fixture/Call"}, func(context.Context, any) (any, error) { return "service-response", nil })
	if err != nil || response != "service-response" {
		return errors.New("RPC outcome changed")
	}
	if !safe(out.Bytes(), needle) {
		return errors.New("unary metadata retained fixture or emitted nothing")
	}
	out.Reset()
	stream := embargogrpc.NewStreamServerInterceptor(slog.New(slog.NewJSONHandler(&out, nil)), scanner)
	if err := stream(nil, boundaryServerStream{context: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "/fixture/Stream"}, func(any, grpc.ServerStream) error { return nil }); err != nil {
		return err
	}
	if !safe(out.Bytes(), needle) {
		return errors.New("stream metadata retained fixture or emitted nothing")
	}
	return nil
}

func safe(data []byte, needle string) bool {
	quoted := strconv.Quote(needle)
	return len(data) > 0 && !bytes.Contains(data, []byte(needle)) && !bytes.Contains(data, []byte(quoted[1:len(quoted)-1]))
}

type boundaryServerStream struct {
	grpc.ServerStream
	context func() context.Context
}

func (s boundaryServerStream) Context() context.Context { return s.context() }
