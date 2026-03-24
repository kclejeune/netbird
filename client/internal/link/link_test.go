package link

import (
	"fmt"
	"sync"
	"testing"
)

// mockIface is a minimal mock for testing.
type mockIface struct {
	name   string
	closed bool
}

func (m *mockIface) Name() string  { return m.name }
func (m *mockIface) Close() error  { m.closed = true; return nil }

// errorCloseIface is a mock that returns an error on Close.
type errorCloseIface struct {
	name     string
	closeErr error
}

func (e *errorCloseIface) Name() string  { return e.name }
func (e *errorCloseIface) Close() error  { return e.closeErr }

func TestNewManager_SingleLink(t *testing.T) {
	iface := &mockIface{name: "wg0"}
	mgr := NewManager(iface)

	if mgr.Primary() != iface {
		t.Fatal("Primary() should return the initial interface")
	}
	if mgr.LinkCount() != 1 {
		t.Fatalf("expected 1 link, got %d", mgr.LinkCount())
	}
	if mgr.IsMultiLink() {
		t.Fatal("single link should not report IsMultiLink")
	}
}

func TestNewManager_NilInterface(t *testing.T) {
	mgr := NewManager(nil)

	if mgr.Primary() != nil {
		t.Fatal("Primary() should return nil with no interface")
	}
	if mgr.LinkCount() != 0 {
		t.Fatalf("expected 0 links, got %d", mgr.LinkCount())
	}
}

func TestAddRemoveLink(t *testing.T) {
	primary := &mockIface{name: "wg0"}
	mgr := NewManager(primary)

	secondary := &mockIface{name: "wg1"}
	mgr.AddLink(&Link{
		ID:            "silvus0",
		TransportType: "wireguard",
		Priority:      10,
		Iface:         secondary,
		state:         LinkState{Up: true},
	})

	if mgr.LinkCount() != 2 {
		t.Fatalf("expected 2 links, got %d", mgr.LinkCount())
	}
	if !mgr.IsMultiLink() {
		t.Fatal("should be multi-link")
	}

	err := mgr.RemoveLink("silvus0")
	if err != nil {
		t.Fatalf("RemoveLink: %v", err)
	}
	if !secondary.closed {
		t.Fatal("removed link's interface should be closed")
	}
	if mgr.LinkCount() != 1 {
		t.Fatalf("expected 1 link after removal, got %d", mgr.LinkCount())
	}
}

func TestRemoveLink_NotFound(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	err := mgr.RemoveLink("nonexistent")
	if err == nil {
		t.Fatal("expected error when removing non-existent link")
	}
}

func TestRemoveLink_NilInterface(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.AddLink(&Link{
		ID:    "no-iface",
		Iface: nil,
		state: LinkState{Up: true},
	})

	err := mgr.RemoveLink("no-iface")
	if err != nil {
		t.Fatalf("RemoveLink with nil interface should not error: %v", err)
	}
}

func TestRemoveLink_ClearsPeerCache(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.AddLink(&Link{
		ID:       "wan0",
		Priority: 5,
		Iface:    &mockIface{name: "wg1"},
		state:    LinkState{Up: true},
	})

	// Default has priority 0 (higher than 5), so it should be selected.
	selected := mgr.SelectLink("peer1")
	if selected == nil || selected.ID != "default" {
		t.Fatalf("unexpected link selected: %v", selected)
	}

	// Mark default down, so peer1 gets cached to wan0.
	defaultLink, _ := mgr.GetLink("default")
	defaultLink.UpdateState(LinkState{Up: false})
	mgr.InvalidatePeerCache("peer1")
	selected = mgr.SelectLink("peer1")
	if selected == nil || selected.ID != "wan0" {
		t.Fatalf("expected wan0 after failover, got %v", selected)
	}

	// Remove wan0 — peer cache should be cleared.
	err := mgr.RemoveLink("wan0")
	if err != nil {
		t.Fatalf("RemoveLink: %v", err)
	}

	// SelectLink should now return nil (only default remains, but it's down).
	selected = mgr.SelectLink("peer1")
	if selected != nil {
		t.Fatalf("expected nil after removing cached link, got %s", selected.ID)
	}
}

func TestAddLink_Replace(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})

	mgr.AddLink(&Link{ID: "link1", Iface: &mockIface{name: "wg1"}, state: LinkState{Up: true}})
	mgr.AddLink(&Link{ID: "link1", Iface: &mockIface{name: "wg2"}, state: LinkState{Up: true}})

	// Should still be 2 links (default + link1), not 3.
	if mgr.LinkCount() != 2 {
		t.Fatalf("expected 2 links after replacement, got %d", mgr.LinkCount())
	}

	link, ok := mgr.GetLink("link1")
	if !ok {
		t.Fatal("link1 not found")
	}
	if link.Iface.Name() != "wg2" {
		t.Fatalf("expected replaced interface wg2, got %s", link.Iface.Name())
	}
}

func TestSelectLink_Priority(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})

	mgr.AddLink(&Link{
		ID:       "backup",
		Priority: 10,
		Iface:    &mockIface{name: "wg1"},
		state:    LinkState{Up: true},
	})

	selected := mgr.SelectLink("peer1")
	if selected == nil {
		t.Fatal("SelectLink returned nil")
	}
	if selected.ID != "default" {
		t.Fatalf("expected default link (priority 0), got %s", selected.ID)
	}
}

func TestSelectLink_Failover(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})

	mgr.AddLink(&Link{
		ID:       "backup",
		Priority: 10,
		Iface:    &mockIface{name: "wg1"},
		state:    LinkState{Up: true},
	})

	// Mark default link as down.
	defaultLink, _ := mgr.GetLink("default")
	defaultLink.UpdateState(LinkState{Up: false})
	mgr.InvalidatePeerCache("peer1")

	selected := mgr.SelectLink("peer1")
	if selected == nil {
		t.Fatal("SelectLink returned nil")
	}
	if selected.ID != "backup" {
		t.Fatalf("expected backup link after failover, got %s", selected.ID)
	}
}

func TestSelectLink_AllDown(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})

	defaultLink, _ := mgr.GetLink("default")
	defaultLink.UpdateState(LinkState{Up: false})

	selected := mgr.SelectLink("peer1")
	if selected != nil {
		t.Fatalf("expected nil when all links are down, got %s", selected.ID)
	}
}

func TestSelectLink_NoLinks(t *testing.T) {
	mgr := NewManager(nil)
	selected := mgr.SelectLink("peer1")
	if selected != nil {
		t.Fatal("expected nil with no links")
	}
}

func TestSelectLink_CachedLinkGoesDown(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.AddLink(&Link{
		ID:       "backup",
		Priority: 10,
		Iface:    &mockIface{name: "wg1"},
		state:    LinkState{Up: true},
	})

	selected := mgr.SelectLink("peer1")
	if selected.ID != "default" {
		t.Fatalf("expected default, got %s", selected.ID)
	}

	// Default goes down — should automatically failover on next call.
	defaultLink, _ := mgr.GetLink("default")
	defaultLink.UpdateState(LinkState{Up: false})

	selected = mgr.SelectLink("peer1")
	if selected == nil || selected.ID != "backup" {
		t.Fatalf("expected failover to backup, got %v", selected)
	}
}

func TestUpdateFromConfig(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})

	configs := []LinkConfigMsg{
		{LinkID: "wan0", TransportType: "wireguard", Priority: 5, Cost: 100},
		{LinkID: "silvus0", TransportType: "wireguard", Priority: 10, Cost: 50},
	}

	mgr.UpdateFromConfig(configs)

	if mgr.LinkCount() != 3 {
		t.Fatalf("expected 3 links, got %d", mgr.LinkCount())
	}

	wan, ok := mgr.GetLink("wan0")
	if !ok {
		t.Fatal("wan0 link not found")
	}
	if wan.Priority != 5 {
		t.Fatalf("expected priority 5, got %d", wan.Priority)
	}
	if wan.Cost != 100 {
		t.Fatalf("expected cost 100, got %d", wan.Cost)
	}
	if wan.State().Up {
		t.Fatal("config-created link should be down initially")
	}
}

func TestUpdateFromConfig_UpdatesExisting(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "wan0", Priority: 5, Cost: 100}})
	mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "wan0", Priority: 1, Cost: 200, TransportType: "relay"}})

	wan, _ := mgr.GetLink("wan0")
	if wan.Priority != 1 || wan.Cost != 200 || wan.TransportType != "relay" {
		t.Fatalf("update failed: priority=%d cost=%d transport=%s", wan.Priority, wan.Cost, wan.TransportType)
	}
	if mgr.LinkCount() != 2 {
		t.Fatalf("expected 2 links, got %d", mgr.LinkCount())
	}
}

func TestUpdateFromConfig_MarksRemovedLinksDown(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "wan0"}, {LinkID: "silvus0"}})

	silvus, _ := mgr.GetLink("silvus0")
	silvus.UpdateState(LinkState{Up: true})

	mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "wan0"}})

	silvus, ok := mgr.GetLink("silvus0")
	if !ok {
		t.Fatal("silvus0 should still exist (not removed)")
	}
	if silvus.State().Up {
		t.Fatal("silvus0 should be marked down")
	}
}

func TestUpdateFromConfig_DefaultLinkPreserved(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "wan0"}})

	defaultLink, _ := mgr.GetLink("default")
	if !defaultLink.State().Up {
		t.Fatal("default link should remain up regardless of config updates")
	}
}

func TestLinks_ReturnsCopy(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.AddLink(&Link{ID: "extra", Iface: &mockIface{name: "wg1"}, state: LinkState{Up: true}})

	links := mgr.Links()
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
}

func TestLinkState_ThreadSafety(t *testing.T) {
	l := &Link{ID: "test", state: LinkState{Up: true}}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.UpdateState(LinkState{Up: true, LatencyMs: 42})
		}()
		go func() {
			defer wg.Done()
			_ = l.State()
		}()
	}
	wg.Wait()
}

func TestConcurrentSelectAndUpdate(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	for i := 0; i < 5; i++ {
		mgr.AddLink(&Link{
			ID:       fmt.Sprintf("link%d", i),
			Priority: uint32(i + 1),
			Iface:    &mockIface{name: fmt.Sprintf("wg%d", i+1)},
			state:    LinkState{Up: true},
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			_ = mgr.SelectLink(peer)
		}(fmt.Sprintf("peer%d", i))
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.UpdateFromConfig([]LinkConfigMsg{{LinkID: "dynamic", Priority: 3}})
		}()
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			mgr.InvalidatePeerCache(peer)
		}(fmt.Sprintf("peer%d", i%10))
	}

	wg.Wait()
}

func TestClose(t *testing.T) {
	iface1 := &mockIface{name: "wg0"}
	iface2 := &mockIface{name: "wg1"}

	mgr := NewManager(iface1)
	mgr.AddLink(&Link{ID: "extra", Iface: iface2, state: LinkState{Up: true}})

	err := mgr.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !iface1.closed || !iface2.closed {
		t.Fatal("all interfaces should be closed")
	}
	if mgr.LinkCount() != 0 {
		t.Fatalf("expected 0 links after close, got %d", mgr.LinkCount())
	}
}

func TestClose_ReturnsFirstError(t *testing.T) {
	errClose := fmt.Errorf("close failed")

	mgr := NewManager(&errorCloseIface{name: "wg0", closeErr: errClose})
	mgr.AddLink(&Link{ID: "extra", Iface: &mockIface{name: "wg1"}, state: LinkState{Up: true}})

	err := mgr.Close()
	if err == nil {
		t.Fatal("expected error from Close")
	}
}

func TestClose_NilInterfaceLinks(t *testing.T) {
	mgr := NewManager(nil)
	mgr.AddLink(&Link{ID: "nil-link", Iface: nil, state: LinkState{Up: true}})

	err := mgr.Close()
	if err != nil {
		t.Fatalf("Close with nil interfaces should not error: %v", err)
	}
}
