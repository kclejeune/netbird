package link

import (
	"fmt"
	"sync"
	"testing"
)

// mockIface is a minimal lifecycle-only interface for tests.
type mockIface struct {
	name   string
	closed bool
}

func (m *mockIface) Name() string { return m.name }
func (m *mockIface) Close() error { m.closed = true; return nil }

// errorCloseIface returns an error on Close.
type errorCloseIface struct {
	name     string
	closeErr error
}

func (e *errorCloseIface) Name() string { return e.name }
func (e *errorCloseIface) Close() error { return e.closeErr }

// ownedLink builds a Manager-owned interface-link (closed on teardown).
func ownedLink(id string, priority uint32, iface Iface, up bool) *Link {
	return &Link{
		ID:            id,
		TransportType: "wireguard",
		Priority:      priority,
		Iface:         iface,
		ownsIface:     true,
		state:         LinkState{Up: up},
	}
}

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
	// Default link must be engine-owned (not closed by Manager).
	def, ok := mgr.GetLink(PrimaryLinkID)
	if !ok || def.ownsIface {
		t.Fatal("default link should exist and be engine-owned (ownsIface=false)")
	}
}

func TestNewManager_NilInterface(t *testing.T) {
	mgr := NewManager(nil)
	if mgr.Primary() != nil {
		t.Fatal("Primary() should be nil with no interface")
	}
	if mgr.LinkCount() != 0 {
		t.Fatalf("expected 0 links, got %d", mgr.LinkCount())
	}
}

// TestClose_DoesNotClosePrimary is the regression test for the double-close bug:
// the Manager must not close the engine-owned primary interface.
func TestClose_DoesNotClosePrimary(t *testing.T) {
	primary := &mockIface{name: "wg0"}
	mgr := NewManager(primary)

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if primary.closed {
		t.Fatal("Manager.Close must NOT close the engine-owned primary interface")
	}
	if mgr.LinkCount() != 0 {
		t.Fatalf("expected 0 links after close, got %d", mgr.LinkCount())
	}
}

func TestClose_ClosesOwnedLinks(t *testing.T) {
	primary := &mockIface{name: "wg0"}
	mesh := &mockIface{name: "mesh0"}
	mgr := NewManager(primary)
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, mesh, true))

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if primary.closed {
		t.Fatal("primary must not be closed by Manager")
	}
	if !mesh.closed {
		t.Fatal("owned mesh link must be closed by Manager")
	}
}

func TestRegisterRemoveInterfaceLink(t *testing.T) {
	primary := &mockIface{name: "wg0"}
	mgr := NewManager(primary)

	mesh := &mockIface{name: "mesh0"}
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, mesh, true))
	if mgr.LinkCount() != 2 || !mgr.IsMultiLink() {
		t.Fatalf("expected 2 links (multi), got %d", mgr.LinkCount())
	}

	if err := mgr.RemoveInterfaceLink("mesh0"); err != nil {
		t.Fatalf("RemoveInterfaceLink: %v", err)
	}
	if !mesh.closed {
		t.Fatal("owned link's interface should be closed on removal")
	}
	if mgr.LinkCount() != 1 {
		t.Fatalf("expected 1 link after removal, got %d", mgr.LinkCount())
	}
}

func TestRemoveInterfaceLink_NotFound(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	if err := mgr.RemoveInterfaceLink("nope"); err == nil {
		t.Fatal("expected error removing unknown link")
	}
}

func TestRegisterInterfaceLink_ReplaceClosesOldOwned(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	old := &mockIface{name: "mesh-old"}
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, old, true))
	newer := &mockIface{name: "mesh-new"}
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, newer, true))

	if !old.closed {
		t.Fatal("replaced owned interface should be closed")
	}
	l, _ := mgr.GetLink("mesh0")
	if l.Iface.Name() != "mesh-new" {
		t.Fatalf("expected replaced interface mesh-new, got %s", l.Iface.Name())
	}
}

// --- SelectLink -----------------------------------------------------------

func TestSelectLink_NoReachability_FallsBackToPrimary(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 5, &mockIface{name: "mesh0"}, true))

	// A peer with no reachability entries must select the primary, even though a
	// higher-priority mesh link exists — mesh links only serve their own peers.
	sel := mgr.SelectLink("ice-peer")
	if sel == nil || sel.ID != PrimaryLinkID {
		t.Fatalf("expected primary fallback, got %v", sel)
	}
}

func TestSelectLink_Reachability_PicksBestUp(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("wan0", 5, &mockIface{name: "wan0"}, true))
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "mesh0"}, true))

	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "wan0"}, {LinkID: "mesh0"}})
	sel := mgr.SelectLink("peerA")
	if sel == nil || sel.ID != "wan0" {
		t.Fatalf("expected wan0 (priority 5), got %v", sel)
	}
}

func TestSelectLink_Failover_WhenBestGoesDown(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("wan0", 5, &mockIface{name: "wan0"}, true))
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "mesh0"}, true))
	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "wan0"}, {LinkID: "mesh0"}})

	if sel := mgr.SelectLink("peerA"); sel.ID != "wan0" {
		t.Fatalf("expected wan0 first, got %s", sel.ID)
	}
	// wan0 goes down -> failover to mesh0 on next select (no manual invalidation).
	wan, _ := mgr.GetLink("wan0")
	wan.UpdateState(LinkState{Up: false})
	if sel := mgr.SelectLink("peerA"); sel == nil || sel.ID != "mesh0" {
		t.Fatalf("expected failover to mesh0, got %v", sel)
	}
}

// TestSelectLink_NoStickAfterRecovery is the regression for cache stickiness:
// once a strictly-higher-priority link recovers, selection must move back to it.
func TestSelectLink_NoStickAfterRecovery(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("wan0", 5, &mockIface{name: "wan0"}, true))
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "mesh0"}, true))
	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "wan0"}, {LinkID: "mesh0"}})

	wan, _ := mgr.GetLink("wan0")
	wan.UpdateState(LinkState{Up: false})
	if sel := mgr.SelectLink("peerA"); sel.ID != "mesh0" {
		t.Fatalf("expected mesh0 while wan0 down, got %s", sel.ID)
	}
	// wan0 recovers -> must switch back, not stick to mesh0.
	wan.UpdateState(LinkState{Up: true})
	if sel := mgr.SelectLink("peerA"); sel == nil || sel.ID != "wan0" {
		t.Fatalf("expected switch back to wan0 after recovery, got %v", sel)
	}
}

func TestSelectLink_AllDown(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	def, _ := mgr.GetLink(PrimaryLinkID)
	def.UpdateState(LinkState{Up: false})
	if sel := mgr.SelectLink("peerA"); sel != nil {
		t.Fatalf("expected nil when all candidates down, got %s", sel.ID)
	}
}

func TestSelectLink_NoLinks(t *testing.T) {
	mgr := NewManager(nil)
	if sel := mgr.SelectLink("peerA"); sel != nil {
		t.Fatal("expected nil with no links")
	}
}

func TestSelectLink_ReachabilityToUnknownLink(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	// Peer references a link that has no interface-link registered -> no
	// candidates -> nil (it does NOT silently fall back to primary, because the
	// peer explicitly declared a non-primary reachability set).
	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "ghost"}})
	if sel := mgr.SelectLink("peerA"); sel != nil {
		t.Fatalf("expected nil for unknown link reachability, got %s", sel.ID)
	}
}

// --- SetPeerLinks ---------------------------------------------------------

func TestSetPeerLinks_ClearFallsBackToPrimary(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 5, &mockIface{name: "mesh0"}, true))
	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "mesh0"}})
	if sel := mgr.SelectLink("peerA"); sel.ID != "mesh0" {
		t.Fatalf("expected mesh0, got %s", sel.ID)
	}
	// Clear reachability -> primary fallback.
	mgr.SetPeerLinks("peerA", nil)
	if sel := mgr.SelectLink("peerA"); sel.ID != PrimaryLinkID {
		t.Fatalf("expected primary after clear, got %s", sel.ID)
	}
}

func TestSetPeerLinks_PerPeerNoCollision(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("wan0", 5, &mockIface{name: "wan0"}, true))

	// Two peers both reference "wan0" but with distinct endpoints. The endpoints
	// must not collide (the old global-flatten model lost this).
	mgr.SetPeerLinks("peerA", []PeerLink{{LinkID: "wan0", Endpoint: "10.0.0.1:51820"}})
	mgr.SetPeerLinks("peerB", []PeerLink{{LinkID: "wan0", Endpoint: "10.0.0.2:51820"}})

	a := mgr.PeerLinks("peerA")
	b := mgr.PeerLinks("peerB")
	if len(a) != 1 || a[0].Endpoint != "10.0.0.1:51820" {
		t.Fatalf("peerA endpoint wrong: %+v", a)
	}
	if len(b) != 1 || b[0].Endpoint != "10.0.0.2:51820" {
		t.Fatalf("peerB endpoint wrong: %+v", b)
	}
}

// --- concurrency ----------------------------------------------------------

func TestLinkState_ThreadSafety(t *testing.T) {
	l := &Link{ID: "x", state: LinkState{Up: true}}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); l.UpdateState(LinkState{Up: true, LatencyMs: 42}) }()
		go func() { defer wg.Done(); _ = l.State() }()
	}
	wg.Wait()
}

func TestConcurrentSelectRegisterSet(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	for i := 0; i < 4; i++ {
		mgr.RegisterInterfaceLink(ownedLink(fmt.Sprintf("l%d", i), uint32(i+1), &mockIface{name: fmt.Sprintf("w%d", i)}, true))
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(p string) { defer wg.Done(); _ = mgr.SelectLink(p) }(fmt.Sprintf("peer%d", i))
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			mgr.SetPeerLinks(p, []PeerLink{{LinkID: "l1"}})
		}(fmt.Sprintf("peer%d", i))
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.RegisterInterfaceLink(ownedLink("dyn", 3, &mockIface{name: "dyn"}, true))
		}()
	}
	wg.Wait()
}

func TestClose_ReturnsFirstOwnedError(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(&Link{ID: "bad", Iface: &errorCloseIface{name: "bad", closeErr: fmt.Errorf("boom")}, ownsIface: true, state: LinkState{Up: true}})
	if err := mgr.Close(); err == nil {
		t.Fatal("expected error from owned link Close")
	}
}
