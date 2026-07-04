package babel

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeRuleInstaller records install/remove calls for assertions.
type fakeRuleInstaller struct {
	mu        sync.Mutex
	installed []RuleSpec
	removed   []RuleSpec
}

func (f *fakeRuleInstaller) Install(s RuleSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = append(f.installed, s)
	return nil
}

func (f *fakeRuleInstaller) Remove(s RuleSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, s)
	return nil
}

func (f *fakeRuleInstaller) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.installed), len(f.removed)
}

func TestRouteRuleSpecs(t *testing.T) {
	m := NewManager(Config{ExportTable: 123, MeshPrefix: "100.64.0.0/10"})
	specs := m.RouteRuleSpecs()
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	s := specs[0]
	if s.Priority != DefaultRulePriority {
		t.Fatalf("priority: expected %d, got %d", DefaultRulePriority, s.Priority)
	}
	if s.Table != 123 || s.Dst != "100.64.0.0/10" || s.Family != FamilyV4 {
		t.Fatalf("spec wrong: %+v", s)
	}
	// Priority must sit between NetBird's 105 (main suppress) and 110 (vpn table).
	if !(s.Priority > 105 && s.Priority < 110) {
		t.Fatalf("priority %d must be between 105 and 110", s.Priority)
	}
}

func TestStartStop_InstallsAndRemovesRule(t *testing.T) {
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
	fake := &fakeRuleInstaller{}
	m.SetRuleInstaller(fake)

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ins, _ := fake.counts(); ins != 1 {
		t.Fatalf("expected 1 rule installed on Start, got %d", ins)
	}

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, rem := fake.counts(); rem != 1 {
		t.Fatalf("expected 1 rule removed on Stop, got %d", rem)
	}
}

func TestStart_DisableKernelRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses an sh-based fake binary")
	}
	dir := t.TempDir()
	m := NewManager(Config{
		Enabled:            true,
		BinaryPath:         fakeBabeldBinary(t, dir, false),
		ConfigDir:          dir,
		SocketPath:         filepath.Join(dir, "b.sock"),
		Interfaces:         []string{"wg0"},
		DisableKernelRules: true,
	})
	fake := &fakeRuleInstaller{}
	m.SetRuleInstaller(fake)

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	time.Sleep(20 * time.Millisecond)
	if ins, _ := fake.counts(); ins != 0 {
		t.Fatalf("expected no rules installed when DisableKernelRules, got %d", ins)
	}
}
