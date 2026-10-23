// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Command poc-check is the minimal Tier 3 reference plugin binary.
// What: Serves header-check candidates over loopback gRPC using generic messages.
// Why: Proves the native process contract (trust plus sha256 plus spawn/kill)
// without requiring generated protobuf stubs for the proof of concept.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// ServiceName is the gRPC service name served on loopback.
// What: Stable service identifier shared by the binary and the host dialer.
// Why: A single constant prevents method-path drift between both ends.
const ServiceName = "gash.v1.PocCheck"

// Version is the POC binary version string.
// What: Health-check version reported to the host.
// Why: Lets operators tell reference builds apart in scan logs.
const Version = "1.0.0"

// Metadata mirrors the manifest fields returned by GetMetadata.
// What: JSON-serializable plugin identity exchanged during handshake.
// Why: The host compares it against the manifest pin before running anything.
type Metadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
	Safe        bool     `json:"safe"`
	Deep        bool     `json:"deep"`
	Active      bool     `json:"active"`
	Phase       string   `json:"phase"`
	Order       int      `json:"order"`
	APIVersion  string   `json:"api_version"`
}

// Candidate is the only result a plugin may return.
// What: Target plus oracle reference without any confidence attached.
// Why: Confidence stays engine-owned; the wire format cannot carry it.
type Candidate struct {
	PluginID   string `json:"plugin_id"`
	Target     string `json:"target"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	OracleName string `json:"oracle_name"`
}

// pocMetadata returns the identity pinned by the manifest.
// What: Single source of the POC identity.
// Why: One constructor serves --metadata output and the gRPC handler alike.
func pocMetadata() Metadata {
	return Metadata{
		ID:          "poc-native-header-check",
		Name:        "POC Native Header Check",
		Description: "Minimal Tier 3 reference plugin that asks the engine to verify security headers.",
		Severity:    "low",
		Tags:        []string{"native", "poc", "headers"},
		Safe:        false,
		Deep:        true,
		Active:      true,
		Phase:       "deep",
		Order:       70,
		APIVersion:  "1.0",
	}
}

// pocServiceAPI is the interface matched by the manual service description.
// What: Handler contract for the reference service.
// Why: gRPC registration requires an interface handler type.
type pocServiceAPI interface {
	getMetadata(context.Context, *structpb.Struct) (*structpb.Struct, error)
	run(context.Context, *structpb.Struct) (*structpb.Struct, error)
	health(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

// What: Stateless handler set for metadata, run, and health.
// Why: Statelessness keeps the reference auditable and kill-safe.
type pocServer struct{}

// Ensure pocServer satisfies pocServiceAPI at compile time.
var _ pocServiceAPI = pocServer{}

// getMetadata handles the handshake query.
// What: Returns the pinned identity for host comparison.
// Why: Version or identity mismatch must fail closed before any scan work.
func (pocServer) getMetadata(_ context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	m := pocMetadata()
	_ = req
	return structpb.NewStruct(map[string]any{
		"id":          m.ID,
		"name":        m.Name,
		"description": m.Description,
		"severity":    m.Severity,
		"tags":        strings.Join(m.Tags, ","),
		"safe":        m.Safe,
		"deep":        m.Deep,
		"active":      m.Active,
		"phase":       m.Phase,
		"order":       float64(m.Order),
		"api_version": m.APIVersion,
		"sha_note":    "host verifies binary sha256 against the manifest pin",
	})
}

// run handles one scan target.
// What: Returns a single header-oracle candidate for the given target.
// Why: The engine still verifies the candidate; the binary never reports a finding.
func (pocServer) run(_ context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	target := req.GetFields()["target"].GetStringValue()
	if strings.HasPrefix(target, "sleep://") {
		time.Sleep(10 * time.Second)
	}
	cands := []any{
		map[string]any{
			"plugin_id":   pocMetadata().ID,
			"target":      target,
			"url":         target,
			"method":      "GET",
			"oracle_name": "header",
		},
	}
	return structpb.NewStruct(map[string]any{
		"status":     "ok",
		"candidates": cands,
	})
}

// health handles liveness probes.
// What: Reports a static healthy status plus version.
// Why: The host uses it right after spawn to detect a broken binary early.
func (pocServer) health(_ context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"healthy": true, "version": Version})
}

// methodHandler adapts a structpb handler to a grpc.MethodDesc.
// What: Bridges typed handlers to the manual service description.
// Why: Avoids generated protobuf code while keeping real gRPC transport.
func methodHandler(fn func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error)) func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return fn
}

// serviceDesc is the manual gRPC service description.
// What: Method table for the reference service.
// Why: Hand-written registration keeps the POC free of protoc tooling.
func serviceDesc() grpc.ServiceDesc {
	srv := pocServer{}
	return grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*pocServiceAPI)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetMetadata",
				Handler: methodHandler(func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &structpb.Struct{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.getMetadata(ctx, in)
				}),
			},
			{
				MethodName: "Run",
				Handler: methodHandler(func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &structpb.Struct{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.run(ctx, in)
				}),
			},
			{
				MethodName: "HealthCheck",
				Handler: methodHandler(func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &structpb.Struct{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.health(ctx, in)
				}),
			},
		},
		Streams: []grpc.StreamDesc{},
	}
}

// printMetadata writes the pinned identity as JSON to stdout.
// What: Offline metadata output for `gash plugins test` and validators.
// Why: Lets the host check identity without spawning the gRPC server.
func printMetadata() error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(pocMetadata())
}

// serve listens on loopback and serves the reference service.
// What: Loopback-only gRPC server with a single PORT announcement line.
// Why: Loopback binding plus stdout discipline keeps the POC network-safe.
func serve(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// Only line ever written to stdout; everything else goes to stderr.
	fmt.Printf("GASH_POC_PORT=%d\n", lis.Addr().(*net.TCPAddr).Port)
	s := grpc.NewServer()
	desc := serviceDesc()
	s.RegisterService(&desc, pocServer{})
	return s.Serve(lis)
}

// dialAndRun is a tiny self-test client used by --selftest.
// What: Spawns nothing; dials an already-serving address and runs once.
// Why: Gives CI a one-process smoke path for the wire format.
func dialAndRun(addr, target string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in, _ := structpb.NewStruct(map[string]any{"target": target})
	out := &structpb.Struct{}
	if err := conn.Invoke(ctx, "/"+ServiceName+"/Run", in, out); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out.AsMap())
}

func main() {
	metadata := flag.Bool("metadata", false, "print plugin metadata JSON and exit")
	serveFlag := flag.Bool("serve", false, "serve gRPC on loopback")
	port := flag.Int("port", 0, "port for --serve (0 selects a free loopback port)")
	selftest := flag.String("selftest", "", "dial ADDR and run once against TARGET=addr (format host:port)")
	target := flag.String("target", "http://example.com/", "target for --selftest run")
	flag.Parse()
	switch {
	case *metadata:
		if err := printMetadata(); err != nil {
			fmt.Fprintln(os.Stderr, "poc-check:", err)
			os.Exit(1)
		}
	case *serveFlag:
		if err := serve(*port); err != nil {
			fmt.Fprintln(os.Stderr, "poc-check:", err)
			os.Exit(1)
		}
	case *selftest != "":
		if err := dialAndRun(*selftest, *target); err != nil {
			fmt.Fprintln(os.Stderr, "poc-check:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: poc-check --metadata | --serve [--port N] | --selftest ADDR [--target URL]")
		os.Exit(2)
	}
}
