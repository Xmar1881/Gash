// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package loader spawns Tier 3 reference binaries over loopback gRPC.
// What: Trust-gated spawn, handshake, run, and kill for native POC plugins.
// Why: Gives the Tier 3 proof of concept a small auditable lifecycle without
// pulling the full broker stack into the reference path.
package loader

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// pocServiceName is the gRPC service served by the reference binary.
// What: Method prefix shared with the POC server implementation.
// Why: A single constant keeps dial paths identical on both ends.
const pocServiceName = "gash.v1.PocCheck"

// POCClient is a live reference plugin process plus its gRPC connection.
// What: Spawned binary handle with handshake already verified.
// Why: Bundling process and connection guarantees every exit path kills.
type POCClient struct {
	cmd  *exec.Cmd
	conn *grpc.ClientConn
	addr string
}

// ResolveTier3Binary resolves a manifest binary field to an executable path.
// What: Manifest-relative lookup with a Windows .exe fallback.
// Why: Keeps manifests portable while Windows builds keep their extension.
func ResolveTier3Binary(manifestPath, binaryField string) string {
	if filepath.IsAbs(binaryField) {
		return binaryField
	}
	candidate := filepath.Join(filepath.Dir(manifestPath), binaryField)
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		return candidate
	}
	if exe := candidate + ".exe"; true {
		if st, err := os.Stat(exe); err == nil && !st.IsDir() {
			return exe
		}
	}
	return candidate
}

// SpawnPOC verifies trust plus digest, spawns the binary, and handshakes.
// What: Fail-closed Tier 3 startup used by scans and tests.
// Why: No handshake or digest match means no process and no finding.
func SpawnPOC(ctx context.Context, manifestPath string, m *Tier3Manifest, trustDB map[string]string, startupTimeout time.Duration) (*POCClient, error) {
	if m == nil {
		return nil, fmt.Errorf("tier3 spawn: nil manifest: %w", plugin.ErrValidation)
	}
	if err := CheckTrust(m, trustDB); err != nil {
		return nil, err
	}
	bin := ResolveTier3Binary(manifestPath, m.Binary)
	if err := VerifySHA256(bin, m.SHA256); err != nil {
		// On Windows the manifest may pin the extensionless name while the
		// built file carries .exe; ResolveTier3Binary already prefers the
		// existing file, so a mismatch here is a real integrity failure.
		return nil, err
	}
	if m.Protocol != "grpc" {
		return nil, fmt.Errorf("tier3 spawn: protocol must be grpc (got %q): %w", m.Protocol, plugin.ErrValidation)
	}
	if startupTimeout <= 0 {
		startupTimeout = 10 * time.Second
	}
	cmd := exec.Command(bin, "--serve", "--port", "0")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("tier3 spawn: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tier3 spawn: start %s: %w", bin, err)
	}
	portCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		if sc.Scan() {
			portCh <- strings.TrimSpace(sc.Text())
			return
		}
		if err := sc.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- fmt.Errorf("tier3 spawn: no port announcement")
	}()
	var portLine string
	select {
	case portLine = <-portCh:
	case err := <-errCh:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("tier3 spawn: read port: %w", err)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("tier3 spawn: context: %w", ctx.Err())
	case <-time.After(startupTimeout):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("tier3 spawn: startup timeout: %w", plugin.ErrTimeout)
	}
	const prefix = "GASH_POC_PORT="
	if !strings.HasPrefix(portLine, prefix) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("tier3 spawn: bad announcement %q: %w", portLine, plugin.ErrValidation)
	}
	addr := "127.0.0.1:" + strings.TrimPrefix(portLine, prefix)
	dialCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("tier3 spawn: dial %s: %w", addr, err)
	}
	client := &POCClient{cmd: cmd, conn: conn, addr: addr}
	if err := client.checkHandshake(ctx, m, startupTimeout); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// checkHandshake compares binary identity plus API version against the manifest.
// What: Application-level handshake over the gRPC channel.
// Why: Version or identity drift must fail closed before any candidate flows.
func (c *POCClient) checkHandshake(ctx context.Context, m *Tier3Manifest, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	in, _ := structpb.NewStruct(map[string]any{"host_api_version": "1.0"})
	out := &structpb.Struct{}
	if err := c.conn.Invoke(callCtx, "/"+pocServiceName+"/GetMetadata", in, out); err != nil {
		return fmt.Errorf("tier3 handshake: metadata: %w", err)
	}
	fields := out.GetFields()
	gotID := fields["id"].GetStringValue()
	gotAPI := fields["api_version"].GetStringValue()
	if gotID != "" && gotID != m.ID {
		return fmt.Errorf("tier3 handshake: id mismatch (manifest=%q binary=%q): %w", m.ID, gotID, plugin.ErrValidation)
	}
	if gotAPI != "1.0" || m.APIVersion != "1.0" {
		return fmt.Errorf("tier3 handshake: api version mismatch (host=1.0 plugin=%q): %w", gotAPI, plugin.ErrValidation)
	}
	healthIn, _ := structpb.NewStruct(map[string]any{})
	healthOut := &structpb.Struct{}
	healthCtx, healthCancel := context.WithTimeout(ctx, timeout)
	defer healthCancel()
	if err := c.conn.Invoke(healthCtx, "/"+pocServiceName+"/HealthCheck", healthIn, healthOut); err != nil {
		return fmt.Errorf("tier3 handshake: health: %w", err)
	}
	if !healthOut.GetFields()["healthy"].GetBoolValue() {
		return fmt.Errorf("tier3 handshake: unhealthy: %w", plugin.ErrValidation)
	}
	return nil
}

// Run asks the binary for candidates with a per-call deadline.
// What: Single target execution over the established channel.
// Why: Per-call timeouts keep a hung binary from stalling the scheduler.
func (c *POCClient) Run(ctx context.Context, target string, timeout time.Duration) ([]plugin.Candidate, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	in, err := structpb.NewStruct(map[string]any{"target": target})
	if err != nil {
		return nil, fmt.Errorf("tier3 run: request: %w", err)
	}
	out := &structpb.Struct{}
	if err := c.conn.Invoke(callCtx, "/"+pocServiceName+"/Run", in, out); err != nil {
		return nil, fmt.Errorf("tier3 run: invoke: %w", err)
	}
	var cands []plugin.Candidate
	for _, item := range out.GetFields()["candidates"].GetListValue().GetValues() {
		fields := item.GetStructValue().GetFields()
		cands = append(cands, plugin.Candidate{
			PluginID: fields["plugin_id"].GetStringValue(),
			Target:   fields["target"].GetStringValue(),
			InjectionPoint: plugin.InjectionPoint{
				URL: fields["url"].GetStringValue(), Method: fields["method"].GetStringValue(),
			},
			OracleName: fields["oracle_name"].GetStringValue(),
		})
	}
	return cands, nil
}

// Close terminates the connection and kills the process.
// What: Unconditional cleanup for every spawn path.
// Why: Deferred Close in callers guarantees no orphan plugin processes.
func (c *POCClient) Close() error {
	var firstErr error
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.cmd != nil && c.cmd.Process != nil {
		// Best effort SIGTERM equivalent: immediate kill is the portable
		// guarantee; graceful shutdown is the binary's own concern.
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
	return firstErr
}

// Addr returns the loopback address of the spawned binary.
// What: Dial address accessor for diagnostics.
// Why: Tests assert loopback-only binding through this value.
func (c *POCClient) Addr() string { return c.addr }
