package babel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Fatal("default config should have Enabled=false")
	}
	if cfg.BinaryPath != DefaultBabelBinary {
		t.Fatalf("expected binary path %q, got %q", DefaultBabelBinary, cfg.BinaryPath)
	}
	if cfg.SocketPath != DefaultSocketPath {
		t.Fatalf("expected socket path %q, got %q", DefaultSocketPath, cfg.SocketPath)
	}
	if cfg.HelloInterval != DefaultHelloInterval {
		t.Fatalf("expected hello interval %d, got %d", DefaultHelloInterval, cfg.HelloInterval)
	}
	if cfg.UpdateInterval != DefaultUpdateInterval {
		t.Fatalf("expected update interval %d, got %d", DefaultUpdateInterval, cfg.UpdateInterval)
	}
}

func TestNewManager_Defaults(t *testing.T) {
	mgr := NewManager(Config{})

	if mgr.config.BinaryPath != DefaultBabelBinary {
		t.Fatalf("expected default binary path, got %q", mgr.config.BinaryPath)
	}
	if mgr.socketPath != DefaultSocketPath {
		t.Fatalf("expected default socket path, got %q", mgr.socketPath)
	}
}

func TestNewManager_CustomConfig(t *testing.T) {
	cfg := Config{
		BinaryPath:     "/usr/local/bin/babeld",
		SocketPath:     "/tmp/babel-test.sock",
		HelloInterval:  2,
		UpdateInterval: 8,
		RouterID:       "192.168.1.1",
		Interfaces:     []string{"wg0", "wg1"},
	}

	mgr := NewManager(cfg)
	if mgr.config.BinaryPath != cfg.BinaryPath {
		t.Fatalf("expected binary path %q, got %q", cfg.BinaryPath, mgr.config.BinaryPath)
	}
	if mgr.socketPath != cfg.SocketPath {
		t.Fatalf("expected socket path %q, got %q", cfg.SocketPath, mgr.socketPath)
	}
}

// TestBuildArgs verifies babeld is invoked config-file-driven and in the
// foreground (no -D, no flag soup) so the supervising Wait is meaningful.
func TestBuildArgs(t *testing.T) {
	mgr := NewManager(Config{Interfaces: []string{"wg0"}})
	args := mgr.buildArgs("/etc/babel/babel.conf")

	if len(args) != 2 || args[0] != "-c" || args[1] != "/etc/babel/babel.conf" {
		t.Fatalf("expected [-c <path>], got %v", args)
	}
	argStr := strings.Join(args, " ")
	for _, bad := range []string{"-D", "-S ", "-G", "-r"} {
		if strings.Contains(argStr, bad) {
			t.Fatalf("args must not contain %q (moved to config file): %v", bad, args)
		}
	}
}

func TestGenerateConfig(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(Config{
		ConfigDir:      tmpDir,
		SocketPath:     filepath.Join(tmpDir, "babel.sock"),
		HelloInterval:  2,
		UpdateInterval: 8,
		RouterID:       "1.2.3.4",
		ExportTable:    123,
		MeshPrefix:     "100.64.0.0/10",
		Interfaces:     []string{"wg0", "wg-manet"},
	})

	configPath, err := mgr.generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	if configPath != filepath.Join(tmpDir, "babel.conf") {
		t.Fatalf("unexpected config path %q", configPath)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	cfg := string(content)

	wants := []string{
		"state-file ",
		"local-path-readwrite \"" + filepath.Join(tmpDir, "babel.sock") + "\"",
		"export-table 123",
		"router-id 1.2.3.4",
		"redistribute ip 100.64.0.0/10 allow",
		"redistribute local deny",
		"interface wg0 type tunnel hello-interval 2 update-interval 8",
		"interface wg-manet type tunnel hello-interval 2 update-interval 8",
	}
	for _, w := range wants {
		if !strings.Contains(cfg, w) {
			t.Fatalf("config missing %q\n---\n%s", w, cfg)
		}
	}
}

func TestGenerateConfig_RedistributeLocalAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(Config{ConfigDir: tmpDir, RedistributeLocal: true, Interfaces: []string{"wg0"}})
	path, err := mgr.generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "redistribute local deny") {
		t.Fatal("should not deny local redistribution when RedistributeLocal is true")
	}
}

func TestGenerateConfig_NoRouterID(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(Config{ConfigDir: tmpDir, Interfaces: []string{"wg0"}})
	path, err := mgr.generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "router-id ") {
		t.Fatal("should not emit router-id when empty")
	}
}

func TestParseRoute(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RouteEntry
	}{
		{
			name: "full route",
			line: "add route 1234 prefix 10.0.0.0/24 installed metric 256 via fe80::1 if wg0",
			expected: &RouteEntry{
				Prefix:    "10.0.0.0/24",
				Metric:    256,
				NextHop:   "fe80::1",
				Interface: "wg0",
				Installed: true,
			},
		},
		{
			name: "route without installed",
			line: "add route 5678 prefix 10.1.0.0/24 metric 512 via fe80::2 if wg1",
			expected: &RouteEntry{
				Prefix:    "10.1.0.0/24",
				Metric:    512,
				NextHop:   "fe80::2",
				Interface: "wg1",
				Installed: false,
			},
		},
		{
			name:     "empty prefix",
			line:     "add route 9999 metric 100",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRoute(tt.line)
			if tt.expected == nil {
				if result != nil {
					t.Fatalf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Prefix != tt.expected.Prefix {
				t.Fatalf("prefix: expected %q, got %q", tt.expected.Prefix, result.Prefix)
			}
			if result.Metric != tt.expected.Metric {
				t.Fatalf("metric: expected %d, got %d", tt.expected.Metric, result.Metric)
			}
			if result.NextHop != tt.expected.NextHop {
				t.Fatalf("nexthop: expected %q, got %q", tt.expected.NextHop, result.NextHop)
			}
			if result.Interface != tt.expected.Interface {
				t.Fatalf("interface: expected %q, got %q", tt.expected.Interface, result.Interface)
			}
			if result.Installed != tt.expected.Installed {
				t.Fatalf("installed: expected %v, got %v", tt.expected.Installed, result.Installed)
			}
		})
	}
}

func TestParseNeighbour(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *NeighbourEntry
	}{
		{
			name: "full neighbour",
			line: "add neighbour 1234 address fe80::1 if wg0 cost 256 rtt 12.5",
			expected: &NeighbourEntry{
				Address:   "fe80::1",
				Interface: "wg0",
				Cost:      256,
				RTT:       12.5,
			},
		},
		{
			name: "neighbour without rtt",
			line: "add neighbour 5678 address fe80::2 if wg1 cost 512",
			expected: &NeighbourEntry{
				Address:   "fe80::2",
				Interface: "wg1",
				Cost:      512,
				RTT:       0,
			},
		},
		{
			name:     "missing address",
			line:     "add neighbour 9999 if wg0 cost 100",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNeighbour(tt.line)
			if tt.expected == nil {
				if result != nil {
					t.Fatalf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Address != tt.expected.Address {
				t.Fatalf("address: expected %q, got %q", tt.expected.Address, result.Address)
			}
			if result.Interface != tt.expected.Interface {
				t.Fatalf("interface: expected %q, got %q", tt.expected.Interface, result.Interface)
			}
			if result.Cost != tt.expected.Cost {
				t.Fatalf("cost: expected %d, got %d", tt.expected.Cost, result.Cost)
			}
			if result.RTT != tt.expected.RTT {
				t.Fatalf("rtt: expected %f, got %f", tt.expected.RTT, result.RTT)
			}
		})
	}
}

func TestIsRunning_NotStarted(t *testing.T) {
	mgr := NewManager(DefaultConfig())
	if mgr.IsRunning() {
		t.Fatal("should not be running before Start")
	}
}

func TestStop_NotRunning(t *testing.T) {
	mgr := NewManager(DefaultConfig())
	err := mgr.Stop()
	if err != nil {
		t.Fatalf("Stop when not running should not error: %v", err)
	}
}

func TestSetRouteUpdateCallback(t *testing.T) {
	mgr := NewManager(DefaultConfig())
	called := false
	mgr.SetRouteUpdateCallback(func(routes []RouteEntry) {
		called = true
	})

	mgr.mu.RLock()
	cb := mgr.onRouteUpdate
	mgr.mu.RUnlock()

	if cb == nil {
		t.Fatal("callback should be set")
	}
	cb(nil)
	if !called {
		t.Fatal("callback should have been invoked")
	}
}
