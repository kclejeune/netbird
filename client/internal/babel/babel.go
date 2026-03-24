// Package babel manages the babeld routing daemon sidecar for TacMesh.
//
// Babel is a loop-avoiding distance-vector routing protocol (RFC 8966) that
// enables dynamic mesh routing across multiple transport links. This package
// provides lifecycle management for the babeld process and a client for
// communicating with it via the local control socket.
//
// Architecture:
//   - The Manager starts babeld as a child process with appropriate configuration
//   - Communication happens via babeld's local control socket (text protocol)
//   - WireGuard tunnel interfaces are registered with babeld using "type tunnel"
//     (which disables split-horizon, appropriate for tunnel interfaces)
//   - Route metrics from babeld feed into the LinkManager's path selection
package babel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultSocketPath is the default babeld local control socket path.
	DefaultSocketPath = "/var/run/babel.sock"

	// DefaultConfigDir is the directory for babeld configuration files.
	DefaultConfigDir = "/etc/babel"

	// DefaultBabelBinary is the default path to the babeld binary.
	DefaultBabelBinary = "babeld"

	// DefaultHelloInterval is the default Hello interval in seconds.
	DefaultHelloInterval = 4

	// DefaultUpdateInterval is the default route update interval in seconds.
	DefaultUpdateInterval = 16
)

// Config holds the configuration for the Babel manager.
type Config struct {
	// Enabled controls whether Babel routing is active.
	Enabled bool

	// BinaryPath is the path to the babeld binary. Defaults to "babeld".
	BinaryPath string

	// SocketPath is the path to the babeld control socket.
	SocketPath string

	// ConfigDir is the directory for generated babeld config files.
	ConfigDir string

	// HelloInterval is the Hello message interval in seconds.
	HelloInterval int

	// UpdateInterval is the route update interval in seconds.
	UpdateInterval int

	// RouterID is the router identifier. If empty, babeld will auto-generate one.
	RouterID string

	// Interfaces lists the WireGuard interface names to register with babeld.
	Interfaces []string

	// RedistributeLocal controls whether local routes are redistributed.
	RedistributeLocal bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		BinaryPath:     DefaultBabelBinary,
		SocketPath:     DefaultSocketPath,
		ConfigDir:      DefaultConfigDir,
		HelloInterval:  DefaultHelloInterval,
		UpdateInterval: DefaultUpdateInterval,
	}
}

// RouteEntry represents a route learned from babeld.
type RouteEntry struct {
	// Prefix is the destination prefix (e.g., "10.0.0.0/24").
	Prefix string

	// Metric is the composite Babel metric for this route.
	Metric uint32

	// NextHop is the next-hop address.
	NextHop string

	// Interface is the interface name this route was learned on.
	Interface string

	// Installed indicates whether babeld has installed this route in the kernel.
	Installed bool
}

// NeighbourEntry represents a Babel neighbour.
type NeighbourEntry struct {
	// Address is the link-local address of the neighbour.
	Address string

	// Interface is the interface this neighbour was discovered on.
	Interface string

	// Cost is the current cost to this neighbour.
	Cost uint32

	// RTT is the round-trip time in milliseconds.
	RTT float64
}

// Manager manages the babeld sidecar process lifecycle and communication.
type Manager struct {
	mu     sync.RWMutex
	config Config
	cmd    *exec.Cmd
	cancel context.CancelFunc

	running    bool
	socketPath string

	// onRouteUpdate is called when routes change (optional callback).
	onRouteUpdate func([]RouteEntry)
}

// NewManager creates a new Babel manager with the given configuration.
func NewManager(cfg Config) *Manager {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = DefaultBabelBinary
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = DefaultConfigDir
	}
	if cfg.HelloInterval == 0 {
		cfg.HelloInterval = DefaultHelloInterval
	}
	if cfg.UpdateInterval == 0 {
		cfg.UpdateInterval = DefaultUpdateInterval
	}

	return &Manager{
		config:     cfg,
		socketPath: cfg.SocketPath,
	}
}

// SetRouteUpdateCallback sets a callback that is invoked when babeld routes change.
func (m *Manager) SetRouteUpdateCallback(fn func([]RouteEntry)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRouteUpdate = fn
}

// Start launches the babeld process with the configured interfaces.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		log.Info("babel routing is disabled")
		return nil
	}

	if m.running {
		return fmt.Errorf("babeld is already running")
	}

	// Verify babeld binary exists.
	binaryPath, err := exec.LookPath(m.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("babeld binary not found at %q: %w", m.config.BinaryPath, err)
	}

	// Generate configuration file.
	configPath, err := m.generateConfig()
	if err != nil {
		return fmt.Errorf("generate babel config: %w", err)
	}

	// Build babeld command arguments.
	args := m.buildArgs(configPath)

	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	cmd := exec.CommandContext(childCtx, binaryPath, args...)
	cmd.Stdout = log.StandardLogger().WriterLevel(log.DebugLevel)
	cmd.Stderr = log.StandardLogger().WriterLevel(log.WarnLevel)

	log.Infof("starting babeld: %s %s", binaryPath, strings.Join(args, " "))

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start babeld: %w", err)
	}

	m.cmd = cmd
	m.running = true

	// Monitor babeld process in background.
	go m.waitForExit(childCtx)

	return nil
}

// Stop terminates the babeld process.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	if m.cancel != nil {
		m.cancel()
	}

	if m.cmd != nil && m.cmd.Process != nil {
		// Send SIGTERM first for graceful shutdown.
		if err := m.cmd.Process.Signal(os.Interrupt); err != nil {
			log.Warnf("failed to send SIGTERM to babeld: %v", err)
			// Force kill.
			_ = m.cmd.Process.Kill()
		}
	}

	m.running = false
	log.Info("babeld stopped")
	return nil
}

// IsRunning returns whether the babeld process is currently running.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetRoutes queries babeld for the current route table via the control socket.
func (m *Manager) GetRoutes() ([]RouteEntry, error) {
	m.mu.RLock()
	socketPath := m.socketPath
	m.mu.RUnlock()

	return queryRoutes(socketPath)
}

// GetNeighbours queries babeld for the current neighbour table.
func (m *Manager) GetNeighbours() ([]NeighbourEntry, error) {
	m.mu.RLock()
	socketPath := m.socketPath
	m.mu.RUnlock()

	return queryNeighbours(socketPath)
}

// AddInterface tells babeld to monitor a new interface.
func (m *Manager) AddInterface(ifaceName string) error {
	return m.sendCommand(fmt.Sprintf("interface %s type tunnel", ifaceName))
}

// RemoveInterface tells babeld to stop monitoring an interface.
func (m *Manager) RemoveInterface(ifaceName string) error {
	return m.sendCommand(fmt.Sprintf("unmonitor %s", ifaceName))
}

// buildArgs constructs the babeld command-line arguments.
func (m *Manager) buildArgs(configPath string) []string {
	args := []string{
		"-c", configPath,
		"-S", m.socketPath, // local control socket
		"-C", fmt.Sprintf("hello-interval %d", m.config.HelloInterval),
		"-C", fmt.Sprintf("update-interval %d", m.config.UpdateInterval),
		"-D",  // run in foreground (we manage the process)
		"-r",  // do not read kernel routes at startup
		"-G", "0", // no grace period
	}

	if m.config.RouterID != "" {
		args = append(args, "-C", fmt.Sprintf("router-id %s", m.config.RouterID))
	}

	if !m.config.RedistributeLocal {
		args = append(args, "-C", "redistribute local deny")
	}

	// Add interfaces.
	for _, iface := range m.config.Interfaces {
		// "type tunnel" disables split-horizon which is appropriate for WG tunnels.
		args = append(args, "-C", fmt.Sprintf("interface %s type tunnel", iface))
	}

	return args
}

// generateConfig writes a babeld configuration file.
func (m *Manager) generateConfig() (string, error) {
	if err := os.MkdirAll(m.config.ConfigDir, 0o755); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	configPath := filepath.Join(m.config.ConfigDir, "babel.conf")

	var sb strings.Builder
	sb.WriteString("# Auto-generated by TacMesh. Do not edit.\n\n")

	// Default filters: allow mesh prefixes, deny everything else.
	sb.WriteString("# Redistribute only NetBird mesh routes\n")
	sb.WriteString("redistribute ip 100.64.0.0/10 allow\n")
	sb.WriteString("redistribute local deny\n\n")

	// Interface configurations.
	for _, iface := range m.config.Interfaces {
		sb.WriteString(fmt.Sprintf("interface %s type tunnel\n", iface))
	}

	if err := os.WriteFile(configPath, []byte(sb.String()), 0o644); err != nil {
		return "", fmt.Errorf("write config file: %w", err)
	}

	log.Debugf("wrote babel config to %s", configPath)
	return configPath, nil
}

// waitForExit monitors the babeld process and updates running state on exit.
func (m *Manager) waitForExit(ctx context.Context) {
	if m.cmd == nil {
		return
	}

	err := m.cmd.Wait()

	m.mu.Lock()
	m.running = false
	m.mu.Unlock()

	if ctx.Err() != nil {
		// Context was cancelled — expected shutdown.
		log.Info("babeld process exited (shutdown)")
		return
	}

	if err != nil {
		log.Errorf("babeld exited unexpectedly: %v", err)
	} else {
		log.Warn("babeld exited unexpectedly with status 0")
	}
}

// sendCommand sends a command to babeld via the control socket.
func (m *Manager) sendCommand(cmd string) error {
	conn, err := net.DialTimeout("unix", m.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to babel socket %s: %w", m.socketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	_, err = fmt.Fprintf(conn, "%s\n", cmd)
	if err != nil {
		return fmt.Errorf("send command %q: %w", cmd, err)
	}

	// Read response until "ok" or "bad" or timeout.
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "ok" {
			return nil
		}
		if strings.HasPrefix(line, "bad") {
			return fmt.Errorf("babel command %q failed: %s", cmd, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read babel response: %w", err)
	}

	return nil
}

// queryRoutes connects to the babel control socket and queries the route table.
func queryRoutes(socketPath string) ([]RouteEntry, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to babel socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	_, err = fmt.Fprintf(conn, "dump\n")
	if err != nil {
		return nil, fmt.Errorf("send dump command: %w", err)
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "ok" {
			break
		}
		if strings.HasPrefix(line, "add route") {
			route := parseRoute(line)
			if route != nil {
				routes = append(routes, *route)
			}
		}
	}

	return routes, scanner.Err()
}

// queryNeighbours connects to the babel control socket and queries neighbours.
func queryNeighbours(socketPath string) ([]NeighbourEntry, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to babel socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	_, err = fmt.Fprintf(conn, "dump\n")
	if err != nil {
		return nil, fmt.Errorf("send dump command: %w", err)
	}

	var neighbours []NeighbourEntry
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "ok" {
			break
		}
		if strings.HasPrefix(line, "add neighbour") {
			nb := parseNeighbour(line)
			if nb != nil {
				neighbours = append(neighbours, *nb)
			}
		}
	}

	return neighbours, scanner.Err()
}

// parseRoute parses a babeld "add route" line into a RouteEntry.
// Format: "add route <id> prefix <prefix> ... metric <metric> ... via <nexthop> if <iface> ..."
func parseRoute(line string) *RouteEntry {
	fields := strings.Fields(line)
	route := &RouteEntry{}

	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "prefix":
			route.Prefix = fields[i+1]
		case "metric":
			fmt.Sscanf(fields[i+1], "%d", &route.Metric)
		case "via":
			route.NextHop = fields[i+1]
		case "if":
			route.Interface = fields[i+1]
		case "installed":
			route.Installed = true
		}
	}

	if route.Prefix == "" {
		return nil
	}
	return route
}

// parseNeighbour parses a babeld "add neighbour" line into a NeighbourEntry.
// Format: "add neighbour <id> address <addr> if <iface> ... cost <cost> ..."
func parseNeighbour(line string) *NeighbourEntry {
	fields := strings.Fields(line)
	nb := &NeighbourEntry{}

	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "address":
			nb.Address = fields[i+1]
		case "if":
			nb.Interface = fields[i+1]
		case "cost":
			fmt.Sscanf(fields[i+1], "%d", &nb.Cost)
		case "rtt":
			fmt.Sscanf(fields[i+1], "%f", &nb.RTT)
		}
	}

	if nb.Address == "" {
		return nil
	}
	return nb
}
