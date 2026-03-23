package link

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// mockWGIface is a minimal mock for testing.
type mockWGIface struct {
	name   string
	closed bool
}

func (m *mockWGIface) Create() error                              { return nil }
func (m *mockWGIface) IsUserspaceBind() bool                      { return false }
func (m *mockWGIface) Name() string                               { return m.name }
func (m *mockWGIface) Address() wgaddr.Address                    { return wgaddr.Address{} }
func (m *mockWGIface) ToInterface() *net.Interface                { return nil }
func (m *mockWGIface) UpdateAddr(string) error                    { return nil }
func (m *mockWGIface) GetProxy() wgproxy.Proxy                   { return nil }
func (m *mockWGIface) GetProxyPort() uint16                       { return 0 }
func (m *mockWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}
func (m *mockWGIface) RemoveEndpointAddress(string) error              { return nil }
func (m *mockWGIface) RemovePeer(string) error                         { return nil }
func (m *mockWGIface) AddAllowedIP(string, netip.Prefix) error         { return nil }
func (m *mockWGIface) RemoveAllowedIP(string, netip.Prefix) error      { return nil }
func (m *mockWGIface) Close() error                                    { m.closed = true; return nil }
func (m *mockWGIface) SetFilter(device.PacketFilter) error             { return nil }
func (m *mockWGIface) GetFilter() device.PacketFilter                  { return nil }
func (m *mockWGIface) GetDevice() *device.FilteredDevice               { return nil }
func (m *mockWGIface) GetWGDevice() *wgtypes.Device                    { return nil }
func (m *mockWGIface) GetStats() (map[string]configurer.WGStats, error) { return nil, nil }
func (m *mockWGIface) GetNet() *netstack.Net                           { return nil }
func (m *mockWGIface) FullStats() (*configurer.Stats, error)           { return nil, nil }

func TestNewManager_SingleLink(t *testing.T) {
	iface := &mockWGIface{name: "wg0"}
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

func TestAddRemoveLink(t *testing.T) {
	primary := &mockWGIface{name: "wg0"}
	mgr := NewManager(primary)

	secondary := &mockWGIface{name: "wg1"}
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

func TestSelectLink_Priority(t *testing.T) {
	primary := &mockWGIface{name: "wg0"}
	mgr := NewManager(primary)

	// Default link has priority 0 (highest).
	mgr.AddLink(&Link{
		ID:       "backup",
		Priority: 10,
		Iface:    &mockWGIface{name: "wg1"},
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
	primary := &mockWGIface{name: "wg0"}
	mgr := NewManager(primary)

	backup := &Link{
		ID:       "backup",
		Priority: 10,
		Iface:    &mockWGIface{name: "wg1"},
		state:    LinkState{Up: true},
	}
	mgr.AddLink(backup)

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

func TestUpdateFromConfig(t *testing.T) {
	mgr := NewManager(&mockWGIface{name: "wg0"})

	configs := []*mgmProto.LinkConfig{
		{
			LinkId:        "wan0",
			TransportType: "wireguard",
			Priority:      5,
			Cost:          100,
		},
		{
			LinkId:        "silvus0",
			TransportType: "wireguard",
			Priority:      10,
			Cost:          50,
		},
	}

	mgr.UpdateFromConfig(configs)

	// Should have 3 links: default + 2 from config.
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
}

func TestClose(t *testing.T) {
	iface1 := &mockWGIface{name: "wg0"}
	iface2 := &mockWGIface{name: "wg1"}

	mgr := NewManager(iface1)
	mgr.AddLink(&Link{
		ID:    "extra",
		Iface: iface2,
		state: LinkState{Up: true},
	})

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
