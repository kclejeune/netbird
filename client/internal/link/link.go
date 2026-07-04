// Package link provides multi-link transport management for TacMesh.
//
// A Link represents a single network transport path (e.g., a WAN WireGuard
// interface or a Silvus MANET radio interface). The Manager coordinates
// multiple Links, provides per-peer path selection, and presents a unified
// view to the Engine.
//
// The Manager separates two concerns that the earlier design conflated:
//
//   - Interface-links: the actual transport interfaces (e.g. "default",
//     "mesh0"), each wrapping a real interface plus health state. These are
//     registered by the engine as it creates interfaces — never from
//     per-peer wire data.
//
//   - Per-peer reachability: which links a given peer is reachable over, and
//     at what endpoint. This is keyed by peer, so two peers advertising the
//     same link id no longer collide, and "peer X over link Y at endpoint Z"
//     is representable.
//
// In single-link mode (the default) the Manager holds one interface-link,
// "default", and every peer with no explicit reachability falls back to it —
// so behavior is identical to the original single-interface engine.
package link

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// primaryLinkID is the id of the default interface-link that wraps the engine's
// primary WireGuard interface.
const primaryLinkID = "default"

// Iface is the minimal lifecycle contract the Manager needs from a link's
// interface. The full WireGuard interface (iface.WGIface) satisfies it.
type Iface interface {
	Name() string
	Close() error
}

// Programmer is the peer-programming contract used to configure static peers on
// a link's interface. These method signatures are gvisor-free (only the WG
// interface's GetNet pulls netstack), so the Manager can hold programmable
// interfaces without dragging in that dependency. iface.WGIface satisfies it.
type Programmer interface {
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP netip.Prefix) error
	RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error
}

// PeerLink is one reachability entry: a peer is reachable over link LinkID at
// the given static Endpoint, routing AllowedIPs. Endpoint/AllowedIPs are only
// meaningful for static (mesh) links; ICE-managed peers carry no PeerLink and
// fall back to the primary link.
type PeerLink struct {
	LinkID     string
	Endpoint   string
	AllowedIPs []string
}

// LinkState represents the health of a single interface-link.
type LinkState struct {
	Up            bool
	LatencyMs     uint32
	LossPercent   uint32
	BandwidthKbps uint64
	LastProbe     time.Time
}

// Link represents a single interface-link with its interface and health.
type Link struct {
	// ID is the unique identifier for this link (e.g., "default", "mesh0").
	ID string
	// TransportType is the transport type (e.g., "wireguard").
	TransportType string
	// Priority for path selection (lower = preferred). The default link is 0.
	Priority uint32
	// Cost is a routing-protocol metric (e.g. fed from Babel); advisory.
	Cost uint32
	// Iface is the interface for this link (may be nil for a not-yet-created link).
	Iface Iface
	// ownsIface reports whether the Manager is responsible for closing Iface.
	// The primary "default" link is engine-owned (false) so Manager.Close does
	// not double-close the engine's WireGuard interface.
	ownsIface bool

	mu    sync.RWMutex
	state LinkState
}

// NewInterfaceLink builds an interface-link. Set owned=true for interfaces the
// Manager should close on teardown (e.g. mesh links the engine created); false
// for engine-owned interfaces the Manager must not close. New links start Up.
func NewInterfaceLink(id, transportType string, priority uint32, iface Iface, owned bool) *Link {
	return &Link{
		ID:            id,
		TransportType: transportType,
		Priority:      priority,
		Iface:         iface,
		ownsIface:     owned,
		state:         LinkState{Up: true},
	}
}

// State returns the current health state of the link.
func (l *Link) State() LinkState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state
}

// UpdateState updates the link's health state.
func (l *Link) UpdateState(s LinkState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = s
}

// Programmer returns the link's interface as a Programmer if it supports peer
// programming (real WireGuard interfaces do). Returns false for placeholder or
// lifecycle-only interfaces.
func (l *Link) Programmer() (Programmer, bool) {
	p, ok := l.Iface.(Programmer)
	return p, ok
}

// Manager coordinates multiple interface-links and per-peer path selection.
type Manager struct {
	mu        sync.RWMutex
	links     map[string]*Link      // linkID -> interface-link
	primary   string                // id of the primary (default) link
	peerLinks map[string][]PeerLink // peerPubKey -> reachability entries
	byPeer    map[string]string     // peerPubKey -> cached selected linkID
}

// NewManager creates a new link Manager. The primary interface is registered as
// the engine-owned "default" link (ownsIface=false) so the Manager never closes
// the interface the engine owns.
func NewManager(primaryIface Iface) *Manager {
	m := &Manager{
		links:     make(map[string]*Link),
		peerLinks: make(map[string][]PeerLink),
		byPeer:    make(map[string]string),
	}
	if primaryIface != nil {
		m.links[primaryLinkID] = &Link{
			ID:            primaryLinkID,
			TransportType: "wireguard",
			Priority:      0,
			Iface:         primaryIface,
			ownsIface:     false,
			state:         LinkState{Up: true},
		}
		m.primary = primaryLinkID
	}
	return m
}

// Primary returns the primary (default) interface, or nil if none.
func (m *Manager) Primary() Iface {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.links[m.primary]; ok {
		return l.Iface
	}
	return nil
}

// RegisterInterfaceLink adds or replaces an interface-link. Set l.ownsIface true
// for Manager-created interfaces (e.g. mesh links) so they are closed on
// teardown; leave it false for engine-owned interfaces. If replacing an
// owned link, the previous interface is closed.
func (m *Manager) RegisterInterfaceLink(l *Link) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.links[l.ID]; ok {
		log.Infof("replacing link %s (transport=%s)", l.ID, existing.TransportType)
		if existing.ownsIface && existing.Iface != nil && existing.Iface != l.Iface {
			if err := existing.Iface.Close(); err != nil {
				log.Warnf("closing replaced link %s interface: %v", l.ID, err)
			}
		}
	}
	m.links[l.ID] = l
	m.invalidateAllLocked()
	log.Infof("registered link %s (transport=%s, priority=%d, cost=%d, owned=%t)", l.ID, l.TransportType, l.Priority, l.Cost, l.ownsIface)
}

// RemoveInterfaceLink removes an interface-link by id, closing its interface
// only if the Manager owns it. Reachability entries pointing at the link are
// left intact (the peer will fall back on the next SelectLink).
func (m *Manager) RemoveInterfaceLink(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.links[id]
	if !ok {
		return fmt.Errorf("link %s not found", id)
	}
	delete(m.links, id)
	m.invalidateAllLocked()
	log.Infof("removed link %s", id)

	if l.ownsIface && l.Iface != nil {
		return l.Iface.Close()
	}
	return nil
}

// SetPeerLinks sets the reachability entries for a peer (replacing any prior
// set). Passing an empty/nil slice clears the peer's reachability, so it falls
// back to the primary link. This is the per-peer path that replaces the old
// global-flatten UpdateFromConfig.
func (m *Manager) SetPeerLinks(peerPubKey string, links []PeerLink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(links) == 0 {
		delete(m.peerLinks, peerPubKey)
	} else {
		m.peerLinks[peerPubKey] = links
	}
	delete(m.byPeer, peerPubKey)
}

// PeerLinks returns a copy of a peer's reachability entries.
func (m *Manager) PeerLinks(peerPubKey string) []PeerLink {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src := m.peerLinks[peerPubKey]
	if len(src) == 0 {
		return nil
	}
	out := make([]PeerLink, len(src))
	copy(out, src)
	return out
}

// GetLink returns an interface-link by id.
func (m *Manager) GetLink(id string) (*Link, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.links[id]
	return l, ok
}

// Links returns all interface-links.
func (m *Manager) Links() []*Link {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Link, 0, len(m.links))
	for _, l := range m.links {
		out = append(out, l)
	}
	return out
}

// LinkCount returns the number of interface-links.
func (m *Manager) LinkCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.links)
}

// IsMultiLink reports whether more than one interface-link is registered.
func (m *Manager) IsMultiLink() bool {
	return m.LinkCount() > 1
}

// SelectLink chooses the best interface-link for reaching a peer.
//
//   - If the peer has reachability entries, the candidate links are exactly
//     those it is reachable on. Otherwise (the common ICE-peer case) the
//     candidate is the primary link — preserving single-link behavior.
//   - Among candidates that exist and are Up, the lowest Priority wins.
//   - The prior selection is reused only if it is still among the best (up and
//     no strictly-higher-priority candidate is up), so a recovered
//     higher-priority link is picked up instead of sticking to a worse one.
func (m *Manager) SelectLink(peerPubKey string) *Link {
	m.mu.Lock()
	defer m.mu.Unlock()

	candidates := m.candidateLinksLocked(peerPubKey)
	best := bestUpLink(candidates)
	if best == nil {
		delete(m.byPeer, peerPubKey)
		return nil
	}

	// Honor the cache only if the cached link is still exactly the best.
	if cachedID, ok := m.byPeer[peerPubKey]; ok {
		if cached, ok := m.links[cachedID]; ok && cached.State().Up && cached.Priority <= best.Priority {
			return cached
		}
	}

	m.byPeer[peerPubKey] = best.ID
	return best
}

// candidateLinksLocked returns the interface-links a peer may use. Caller holds m.mu.
func (m *Manager) candidateLinksLocked(peerPubKey string) []*Link {
	entries := m.peerLinks[peerPubKey]
	if len(entries) == 0 {
		if l, ok := m.links[m.primary]; ok {
			return []*Link{l}
		}
		return nil
	}
	out := make([]*Link, 0, len(entries))
	for _, e := range entries {
		if l, ok := m.links[e.LinkID]; ok {
			out = append(out, l)
		}
	}
	return out
}

// bestUpLink returns the up link with the lowest Priority, or nil.
func bestUpLink(links []*Link) *Link {
	var best *Link
	for _, l := range links {
		if !l.State().Up {
			continue
		}
		if best == nil || l.Priority < best.Priority {
			best = l
		}
	}
	return best
}

// InvalidatePeerCache drops a peer's cached selection, forcing re-evaluation.
func (m *Manager) InvalidatePeerCache(peerPubKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byPeer, peerPubKey)
}

// invalidateAllLocked clears the whole selection cache. Caller holds m.mu.
func (m *Manager) invalidateAllLocked() {
	if len(m.byPeer) != 0 {
		m.byPeer = make(map[string]string)
	}
}

// Close shuts down the links the Manager owns. The engine-owned primary
// interface is left for the engine to close, avoiding a double-close.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for id, l := range m.links {
		if l.ownsIface && l.Iface != nil {
			if err := l.Iface.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		delete(m.links, id)
	}
	m.peerLinks = make(map[string][]PeerLink)
	m.byPeer = make(map[string]string)
	return firstErr
}
