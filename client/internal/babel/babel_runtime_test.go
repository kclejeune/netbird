package babel

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// startFakeBabeld listens on a unix socket and answers each connection's single
// command line using handler (which returns the full response, including its own
// terminator). It emulates babeld's read-write local interface closely enough to
// exercise the Manager's socket code paths without a real babeld.
func startFakeBabeld(t *testing.T, socketPath string, handler func(cmd string) string) {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				_, _ = c.Write([]byte(handler(strings.TrimSpace(line))))
			}(conn)
		}
	}()
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", msg)
}

func TestGetRoutes_OverSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	startFakeBabeld(t, sock, func(cmd string) string {
		if cmd != "dump" {
			return "ok\n"
		}
		return "add route 1 prefix 100.64.0.0/24 installed metric 256 via fe80::1 if wg0\n" +
			"add route 2 prefix 100.65.0.0/24 metric 512 via fe80::2 if mesh0\n" +
			"add neighbour n1 address fe80::1 if wg0 cost 96 rtt 12.5\n" +
			"ok\n"
	})

	m := NewManager(Config{SocketPath: sock})

	routes, err := m.GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d: %+v", len(routes), routes)
	}
	if routes[0].Prefix != "100.64.0.0/24" || routes[0].Metric != 256 || !routes[0].Installed || routes[0].Interface != "wg0" {
		t.Fatalf("route[0] parsed wrong: %+v", routes[0])
	}
	if routes[1].Installed {
		t.Fatalf("route[1] should not be installed: %+v", routes[1])
	}
}

func TestGetNeighbours_OverSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	startFakeBabeld(t, sock, func(cmd string) string {
		return "add route r1 prefix 100.64.0.0/24 metric 256 via fe80::9 if wg0\n" +
			"add neighbour n1 address fe80::1 if wg0 cost 96 rtt 12.5\n" +
			"add neighbour n2 address fe80::2 if mesh0 cost 300\n" +
			"ok\n"
	})

	m := NewManager(Config{SocketPath: sock})

	nbs, err := m.GetNeighbours()
	if err != nil {
		t.Fatalf("GetNeighbours: %v", err)
	}
	if len(nbs) != 2 {
		t.Fatalf("expected 2 neighbours, got %d: %+v", len(nbs), nbs)
	}
	if nbs[0].Interface != "wg0" || nbs[0].Cost != 96 || nbs[0].RTT != 12.5 {
		t.Fatalf("neighbour[0] parsed wrong: %+v", nbs[0])
	}
	if nbs[1].Interface != "mesh0" || nbs[1].Cost != 300 || nbs[1].RTT != 0 {
		t.Fatalf("neighbour[1] parsed wrong: %+v", nbs[1])
	}
}

func TestSendCommand_OKAndBad(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	startFakeBabeld(t, sock, func(cmd string) string {
		if strings.HasPrefix(cmd, "flush") {
			return "bad no such interface\n"
		}
		return "ok\n"
	})

	m := NewManager(Config{SocketPath: sock})

	if err := m.AddInterface("wg0"); err != nil {
		t.Fatalf("AddInterface (expected ok): %v", err)
	}
	if err := m.RemoveInterface("wg0"); err == nil {
		t.Fatal("RemoveInterface should surface a 'bad' response as an error")
	}
}

func TestGetRoutes_SocketMissing(t *testing.T) {
	m := NewManager(Config{SocketPath: filepath.Join(t.TempDir(), "nope.sock")})
	if _, err := m.GetRoutes(); err == nil {
		t.Fatal("expected error dialing a missing socket")
	}
}

// fakeBabeldBinary writes a tiny executable that ignores its args and blocks
// until SIGTERM (so cmd.Wait models a long-running babeld). Returns its path.
func fakeBabeldBinary(t *testing.T, dir string, exitImmediately bool) string {
	t.Helper()
	bin := filepath.Join(dir, "fakebabeld")
	var script string
	if exitImmediately {
		script = "#!/bin/sh\nexit 0\n"
	} else {
		script = "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.05; done\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake babeld: %v", err)
	}
	return bin
}

func TestManager_ProcessLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses an sh-based fake binary")
	}
	dir := t.TempDir()
	m := NewManager(Config{
		Enabled:    true,
		BinaryPath: fakeBabeldBinary(t, dir, false),
		ConfigDir:  dir,
		SocketPath: filepath.Join(dir, "b.sock"),
		Interfaces: []string{"wg0"},
	})

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsRunning() {
		t.Fatal("expected running after Start")
	}
	// A generated config file should exist.
	if _, err := os.Stat(filepath.Join(dir, "babel.conf")); err != nil {
		t.Fatalf("expected generated config: %v", err)
	}
	// Second Start must be rejected.
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("second Start should error while running")
	}

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if m.IsRunning() {
		t.Fatal("expected not running after Stop")
	}
}

func TestManager_SupervisesUnexpectedExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses an sh-based fake binary")
	}
	dir := t.TempDir()
	m := NewManager(Config{
		Enabled:    true,
		BinaryPath: fakeBabeldBinary(t, dir, true), // exits immediately
		ConfigDir:  dir,
		SocketPath: filepath.Join(dir, "b.sock"),
		Interfaces: []string{"wg0"},
	})

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// waitForExit must observe the early exit and clear running.
	waitFor(t, func() bool { return !m.IsRunning() }, 2*time.Second, "running to clear after process exit")
}

func TestManager_MissingBinaryIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(Config{
		Enabled:    true,
		BinaryPath: "definitely-not-a-real-babeld-xyz",
		ConfigDir:  dir,
		SocketPath: filepath.Join(dir, "b.sock"),
		Interfaces: []string{"wg0"},
	})

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("missing babeld should be non-fatal, got: %v", err)
	}
	if m.IsRunning() {
		t.Fatal("should not be running when the binary is missing")
	}
}

func TestManager_DisabledStartsNothing(t *testing.T) {
	m := NewManager(Config{Enabled: false})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("disabled Start: %v", err)
	}
	if m.IsRunning() {
		t.Fatal("disabled manager should not run")
	}
}
