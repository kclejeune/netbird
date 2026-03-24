// Package link provides multi-link transport management for TacMesh.
//
// A Link represents a single network transport path (e.g., a WAN WireGuard
// interface or a Silvus MANET radio interface). The Manager coordinates
// multiple Links, provides path selection, and presents a unified view to
// the Engine.
//
// In single-link (legacy) mode, the Manager wraps a single WireGuard
// interface and behaves identically to the original NetBird engine.
package link

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Iface is the minimal interface required by the link Manager for lifecycle
// management. The full WireGuard interface (WGIface) satisfies this interface.
// Consumers that need the full WGIface should type-assert the Link.Iface value.
type Iface interface {
	Name() string
	Close() error
}

// LinkConfigMsg is a proto-independent representation of a link configuration
// received from the management server. The engine layer converts from the
// protobuf type to this struct.
type LinkConfigMsg struct {
	LinkID           string
	TransportType    string
	Endpoint         string
	MTU              uint32
	Priority         uint32
	Cost             uint32
	WgIfaceName      string
	MulticastEnabled bool
}

// LinkState represents the health of a single link.
type LinkState struct {
	Up            bool
	LatencyMs     uint32
	LossPercent   uint32
	BandwidthKbps uint64
	LastProbe     time.Time
}

// Link represents a single transport link with its WireGuard interface and metadata.
type Link struct {
	// ID is the unique identifier for this link (e.g., "wan0", "silvus0").
	ID string

	// TransportType is the transport type (e.g., "wireguard", "relay").
	TransportType string

	// Priority for path selection (lower = preferred).
	Priority uint32

	// Cost metric for routing protocol integration.
	Cost uint32

	// Iface is the interface for this link. For WireGuard links this will be
	// the full WGIface; consumers should type-assert to the full interface
	// when they need WG-specific operations.
	Iface Iface

	// Config from management server.
	Config *LinkConfigMsg

	mu    sync.RWMutex
	state LinkState
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

// Manager coordinates multiple transport links.
//
// In single-link mode (the default), it wraps the primary WireGuard interface
// and all operations pass through to it transparently. In multi-link mode,
// it manages multiple Iface instances and provides path selection.
type Manager struct {
	mu      sync.RWMutex
	links   map[string]*Link // linkID -> Link
	primary string           // ID of the primary (default) link
	byPeer  map[string]*Link // peerPubKey -> preferred link (cache)
}

// NewManager creates a new link Manager.
// The primary Iface is registered as the "default" link for backward compatibility.
func NewManager(primaryIface Iface) *Manager {
	m := &Manager{
		links:  make(map[string]*Link),
		byPeer: make(map[string]*Link),
	}

	if primaryIface != nil {
		defaultLink := &Link{
			ID:            "default",
			TransportType: "wireguard",
			Priority:      0,
			Iface:         primaryIface,
			state:         LinkState{Up: true},
		}
		m.links["default"] = defaultLink
		m.primary = "default"
	}

	return m
}

// Primary returns the primary (default) interface.
// This provides backward compatibility with code that expects a single interface.
func (m *Manager) Primary() Iface {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.links[m.primary]; ok {
		return l.Iface
	}
	return nil
}

// AddLink registers a new transport link. If a link with the same ID exists,
// it is replaced.
func (m *Manager) AddLink(l *Link) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.links[l.ID]; ok {
		log.Infof("replacing link %s (transport=%s)", l.ID, existing.TransportType)
	}
	m.links[l.ID] = l
	log.Infof("added link %s (transport=%s, priority=%d, cost=%d)", l.ID, l.TransportType, l.Priority, l.Cost)
}

// RemoveLink removes a transport link by ID and closes its interface.
func (m *Manager) RemoveLink(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.links[id]
	if !ok {
		return fmt.Errorf("link %s not found", id)
	}

	// Clear peer cache entries pointing to this link.
	for k, v := range m.byPeer {
		if v.ID == id {
			delete(m.byPeer, k)
		}
	}

	delete(m.links, id)
	log.Infof("removed link %s", id)

	if l.Iface != nil {
		return l.Iface.Close()
	}
	return nil
}

// GetLink returns a link by ID.
func (m *Manager) GetLink(id string) (*Link, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.links[id]
	return l, ok
}

// Links returns all registered links.
func (m *Manager) Links() []*Link {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Link, 0, len(m.links))
	for _, l := range m.links {
		result = append(result, l)
	}
	return result
}

// LinkCount returns the number of registered links.
func (m *Manager) LinkCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.links)
}

// IsMultiLink returns true if more than one link is registered.
func (m *Manager) IsMultiLink() bool {
	return m.LinkCount() > 1
}

// SelectLink chooses the best link for reaching a given peer.
// The current implementation uses a simple priority-based selection.
// A more sophisticated implementation would consider link health metrics.
func (m *Manager) SelectLink(peerPubKey string) *Link {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check cache first.
	if cached, ok := m.byPeer[peerPubKey]; ok {
		if cached.State().Up {
			return cached
		}
	}

	// Select the lowest-priority (highest-preference) link that is up.
	var best *Link
	for _, l := range m.links {
		if !l.State().Up {
			continue
		}
		if best == nil || l.Priority < best.Priority {
			best = l
		}
	}

	if best != nil {
		m.byPeer[peerPubKey] = best
	}

	return best
}

// InvalidatePeerCache removes cached link selections for a peer,
// forcing re-evaluation on the next SelectLink call.
func (m *Manager) InvalidatePeerCache(peerPubKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byPeer, peerPubKey)
}

// UpdateFromConfig applies link configuration from the management server.
// New links are added, existing links are updated, and links not in the
// config are marked for removal (but not removed, to allow graceful teardown).
func (m *Manager) UpdateFromConfig(linkConfigs []LinkConfigMsg) {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]bool)
	for i := range linkConfigs {
		lc := &linkConfigs[i]
		seen[lc.LinkID] = true

		existing, ok := m.links[lc.LinkID]
		if ok {
			// Update metadata.
			existing.Priority = lc.Priority
			existing.Cost = lc.Cost
			existing.TransportType = lc.TransportType
			existing.Config = lc
			log.Debugf("updated link config for %s", lc.LinkID)
		} else {
			// New link — the interface will be created by the engine when it processes
			// the link config. For now, register a placeholder.
			m.links[lc.LinkID] = &Link{
				ID:            lc.LinkID,
				TransportType: lc.TransportType,
				Priority:      lc.Priority,
				Cost:          lc.Cost,
				Config:        lc,
				state:         LinkState{Up: false},
			}
			log.Infof("registered new link %s from config (transport=%s, pending interface creation)", lc.LinkID, lc.TransportType)
		}
	}

	// Mark links not in config as down (don't remove — let the engine handle teardown).
	for id, l := range m.links {
		if id == "default" {
			continue // Never remove the default link via config updates.
		}
		if !seen[id] {
			l.UpdateState(LinkState{Up: false})
			log.Infof("link %s not in updated config, marked down", id)
		}
	}
}

// Close shuts down all links.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for id, l := range m.links {
		if l.Iface != nil {
			if err := l.Iface.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		delete(m.links, id)
	}
	m.byPeer = make(map[string]*Link)
	return firstErr
}
