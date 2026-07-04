package link

import (
	"testing"
)

func newMonitorFor(mgr *Manager, neigh NeighbourFunc, live LivenessFunc) *Monitor {
	mo := NewMonitor(mgr, DefaultMonitorInterval, neigh, live)
	// Deterministic time for LastProbe assertions is not needed; keep time.Now.
	return mo
}

// TestMonitor_PrimaryAlwaysUp verifies the Monitor never marks the primary link
// down, even with no neighbours and a liveness fn that reports down.
func TestMonitor_PrimaryAlwaysUp(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	// Force default down first to prove the monitor forces it back up.
	def, _ := mgr.GetLink(PrimaryLinkID)
	def.UpdateState(LinkState{Up: false})

	mo := newMonitorFor(mgr, nil, func(string) (bool, uint32) { return false, 0 })
	mo.Tick()

	if !def.State().Up {
		t.Fatal("primary link must be forced up by the monitor")
	}
	if def.State().LastProbe.IsZero() {
		t.Fatal("primary link LastProbe should be set")
	}
}

// TestMonitor_PrimaryLatencyFromNeighbour verifies neighbour RTT annotates the
// primary link's latency without affecting its up state.
func TestMonitor_PrimaryLatencyFromNeighbour(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mo := newMonitorFor(mgr, func() ([]Neighbour, error) {
		return []Neighbour{{Interface: "wg0", RTTMs: 25, Up: true}}, nil
	}, nil)
	mo.Tick()

	def, _ := mgr.GetLink(PrimaryLinkID)
	st := def.State()
	if !st.Up || st.LatencyMs != 25 {
		t.Fatalf("expected primary up with latency 25, got up=%v latency=%d", st.Up, st.LatencyMs)
	}
}

// TestMonitor_MeshUpFromNeighbour verifies a mesh link is brought up (with
// latency) when a live neighbour exists on its interface, and marked down when
// the neighbour disappears.
func TestMonitor_MeshUpFromNeighbour(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "wg-mesh"}, false))

	var haveNeighbour bool
	mo := newMonitorFor(mgr, func() ([]Neighbour, error) {
		if !haveNeighbour {
			return nil, nil
		}
		return []Neighbour{{Interface: "wg-mesh", RTTMs: 40, Up: true}}, nil
	}, nil)

	// No neighbour yet -> mesh down.
	mo.Tick()
	mesh, _ := mgr.GetLink("mesh0")
	if mesh.State().Up {
		t.Fatal("mesh link should be down with no neighbour")
	}

	// Neighbour appears -> mesh up with latency.
	haveNeighbour = true
	mo.Tick()
	if st := mesh.State(); !st.Up || st.LatencyMs != 40 {
		t.Fatalf("expected mesh up latency 40, got up=%v latency=%d", st.Up, st.LatencyMs)
	}

	// Neighbour disappears -> mesh down again.
	haveNeighbour = false
	mo.Tick()
	if mesh.State().Up {
		t.Fatal("mesh link should go down when neighbour disappears")
	}
}

// TestMonitor_MeshLivenessFallback verifies the liveness fn drives a mesh link
// when no neighbour data is available (e.g. babel disabled, static peers).
func TestMonitor_MeshLivenessFallback(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "wg-mesh"}, false))

	up := true
	mo := newMonitorFor(mgr, nil, func(ifn string) (bool, uint32) {
		if ifn == "wg-mesh" {
			return up, 15
		}
		return false, 0
	})

	mo.Tick()
	mesh, _ := mgr.GetLink("mesh0")
	if st := mesh.State(); !st.Up || st.LatencyMs != 15 {
		t.Fatalf("expected mesh up latency 15 from liveness, got up=%v latency=%d", st.Up, st.LatencyMs)
	}

	up = false
	mo.Tick()
	if mesh.State().Up {
		t.Fatal("mesh should be down when liveness reports down")
	}
}

// TestMonitor_AggregateMinRTT verifies multiple neighbours on one interface
// aggregate to the minimum RTT.
func TestMonitor_AggregateMinRTT(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 10, &mockIface{name: "wg-mesh"}, false))

	mo := newMonitorFor(mgr, func() ([]Neighbour, error) {
		return []Neighbour{
			{Interface: "wg-mesh", RTTMs: 80, Up: true},
			{Interface: "wg-mesh", RTTMs: 30, Up: true},
			{Interface: "wg-mesh", RTTMs: 0, Up: false}, // ignored (down)
		}, nil
	}, nil)
	mo.Tick()

	mesh, _ := mgr.GetLink("mesh0")
	if st := mesh.State(); !st.Up || st.LatencyMs != 30 {
		t.Fatalf("expected aggregated min RTT 30, got up=%v latency=%d", st.Up, st.LatencyMs)
	}
}

// TestMonitor_SelectLinkReactsToHealth ties the monitor to selection: a mesh
// peer selects the mesh link only while the monitor keeps it up.
func TestMonitor_SelectLinkReactsToHealth(t *testing.T) {
	mgr := NewManager(&mockIface{name: "wg0"})
	mgr.RegisterInterfaceLink(ownedLink("mesh0", 1, &mockIface{name: "wg-mesh"}, false)) // higher pref than default
	mgr.SetPeerLinks("meshpeer", []PeerLink{{LinkID: "mesh0"}})

	up := true
	mo := newMonitorFor(mgr, nil, func(string) (bool, uint32) { return up, 0 })

	mo.Tick()
	if sel := mgr.SelectLink("meshpeer"); sel == nil || sel.ID != "mesh0" {
		t.Fatalf("expected mesh0 while up, got %v", sel)
	}

	up = false
	mo.Tick()
	if sel := mgr.SelectLink("meshpeer"); sel != nil {
		t.Fatalf("expected no link when mesh down (peer not reachable on primary), got %v", sel)
	}
}
