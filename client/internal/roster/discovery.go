package roster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultBeaconInterval is how often a node announces its presence.
	DefaultBeaconInterval = 5 * time.Second

	// DefaultBeaconMaxSkew bounds how far a received beacon's timestamp may
	// deviate from local time before it is rejected (replay / clock-drift guard).
	DefaultBeaconMaxSkew = 60 * time.Second

	// maxBeaconSize caps a single datagram read.
	maxBeaconSize = 2048
)

// beaconConn is the minimal packet transport the discovery loop needs. A real
// UDP multicast socket (*net.UDPConn) satisfies it; tests inject an in-memory
// fake so two Discovery instances can talk without a network.
type beaconConn interface {
	WriteTo(p []byte, addr net.Addr) (int, error)
	ReadFrom(p []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// DiscoveredPeer is a rostered peer whose endpoint was learned from a beacon.
type DiscoveredPeer struct {
	// Peer is the matching roster entry (identity + allowed IPs).
	Peer Peer
	// Endpoint is the transport endpoint the peer announced.
	Endpoint string
	// Source is the datagram source address (advisory; NAT may rewrite it).
	Source net.Addr
}

// Discovery announces this node's presence and discovers rostered peers over a
// multicast group. Every beacon is signed with the node's HKDF-derived Ed25519
// beacon key and verified against the roster-bound beacon public key, so only
// rostered nodes are ever acted on. Discovered peers are delivered via a
// callback (the engine programs them as WireGuard peers).
type Discovery struct {
	conn       beaconConn
	group      net.Addr
	self       Beacon // announcement template: WGPubKey + Endpoint
	beaconPriv ed25519.PrivateKey
	interval   time.Duration
	maxSkew    time.Duration
	onPeer     func(DiscoveredPeer)
	now        func() time.Time // injectable for tests

	mu     sync.Mutex
	roster *Roster
	// seenTS tracks the last accepted beacon timestamp per peer, rejecting
	// replays and out-of-order duplicates.
	seenTS map[string]int64
	// seenEndpoint tracks the last endpoint delivered per peer, so the callback
	// only fires on first sight or when the endpoint actually changes.
	seenEndpoint map[string]string
}

// DiscoveryConfig configures a Discovery.
type DiscoveryConfig struct {
	// Conn is the packet transport (a joined multicast socket, or a test fake).
	Conn beaconConn
	// Group is the multicast destination beacons are written to.
	Group net.Addr
	// SelfWGPubKey is our WireGuard public key (announced so peers can match us).
	SelfWGPubKey string
	// SelfEndpoint is the transport endpoint we announce. Empty => receive-only
	// (we discover others but do not announce ourselves).
	SelfEndpoint string
	// BeaconPriv is our HKDF-derived Ed25519 beacon signing key.
	BeaconPriv ed25519.PrivateKey
	// Roster authenticates incoming beacons.
	Roster *Roster
	// Interval between announcements (0 => default).
	Interval time.Duration
	// MaxSkew bounds accepted beacon timestamps (0 => default).
	MaxSkew time.Duration
	// OnPeer is invoked for each freshly-discovered / endpoint-changed peer.
	OnPeer func(DiscoveredPeer)
}

// NewDiscovery builds a Discovery from config.
func NewDiscovery(cfg DiscoveryConfig) *Discovery {
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultBeaconInterval
	}
	skew := cfg.MaxSkew
	if skew <= 0 {
		skew = DefaultBeaconMaxSkew
	}
	return &Discovery{
		conn:         cfg.Conn,
		group:        cfg.Group,
		self:         Beacon{WGPubKey: cfg.SelfWGPubKey, Endpoint: cfg.SelfEndpoint},
		beaconPriv:   cfg.BeaconPriv,
		interval:     interval,
		maxSkew:      skew,
		onPeer:       cfg.OnPeer,
		now:          time.Now,
		roster:       cfg.Roster,
		seenTS:       make(map[string]int64),
		seenEndpoint: make(map[string]string),
	}
}

// SetRoster swaps the roster used to authenticate beacons (e.g. after a refresh).
func (d *Discovery) SetRoster(r *Roster) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.roster = r
}

// Run announces (if an endpoint is set) and receives until ctx is cancelled.
func (d *Discovery) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if d.self.Endpoint != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.announceLoop(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.receiveLoop(ctx)
	}()
	wg.Wait()
}

func (d *Discovery) announceLoop(ctx context.Context) {
	t := time.NewTicker(d.interval)
	defer t.Stop()
	d.announce() // announce promptly on start
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.announce()
		}
	}
}

func (d *Discovery) announce() {
	b := Beacon{WGPubKey: d.self.WGPubKey, Endpoint: d.self.Endpoint, Timestamp: d.now().Unix()}
	if err := SignBeacon(&b, d.beaconPriv); err != nil {
		log.Debugf("beacon: sign: %v", err)
		return
	}
	data, err := json.Marshal(&b)
	if err != nil {
		return
	}
	if _, err := d.conn.WriteTo(data, d.group); err != nil {
		log.Debugf("beacon: write: %v", err)
	}
}

func (d *Discovery) receiveLoop(ctx context.Context) {
	buf := make([]byte, maxBeaconSize)
	for {
		if ctx.Err() != nil {
			return
		}
		// Bounded read deadline so ctx cancellation is observed promptly.
		_ = d.conn.SetReadDeadline(d.now().Add(time.Second))
		n, src, err := d.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Debugf("beacon: read: %v", err)
			continue
		}
		d.handle(buf[:n], src)
	}
}

// handle processes one received datagram: parse, skip self, authenticate,
// replay/dedup, and deliver.
func (d *Discovery) handle(data []byte, src net.Addr) {
	var b Beacon
	if err := json.Unmarshal(data, &b); err != nil {
		return
	}
	if b.WGPubKey == "" || b.WGPubKey == d.self.WGPubKey {
		return // ignore our own / malformed beacons
	}

	d.mu.Lock()
	roster := d.roster
	d.mu.Unlock()
	if roster == nil {
		return
	}

	if err := VerifyBeaconAgainstRoster(&b, roster); err != nil {
		log.Debugf("beacon: reject %s: %v", b.WGPubKey, err)
		return
	}

	// Timestamp skew guard (replay / clock drift).
	nowUnix := d.now().Unix()
	skew := int64(d.maxSkew.Seconds())
	if b.Timestamp < nowUnix-skew || b.Timestamp > nowUnix+skew {
		log.Debugf("beacon: %s timestamp out of window", b.WGPubKey)
		return
	}

	peer, _ := roster.FindPeer(b.WGPubKey) // present: VerifyBeaconAgainstRoster passed

	d.mu.Lock()
	if last, ok := d.seenTS[b.WGPubKey]; ok && b.Timestamp <= last {
		d.mu.Unlock()
		return // replay / out-of-order
	}
	d.seenTS[b.WGPubKey] = b.Timestamp
	prevEndpoint, seen := d.seenEndpoint[b.WGPubKey]
	changed := !seen || prevEndpoint != b.Endpoint
	d.seenEndpoint[b.WGPubKey] = b.Endpoint
	cb := d.onPeer
	d.mu.Unlock()

	if changed && cb != nil {
		cb(DiscoveredPeer{Peer: *peer, Endpoint: b.Endpoint, Source: src})
	}
}

// NewMulticastConn joins the given IPv4 multicast group on iface (nil = default)
// and returns a conn usable for both sending and receiving beacons. Linux/std
// net; not exercised by unit tests (needs a real interface).
func NewMulticastConn(group string, iface *net.Interface) (beaconConn, net.Addr, error) {
	gaddr, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve multicast group %q: %w", group, err)
	}
	conn, err := net.ListenMulticastUDP("udp4", iface, gaddr)
	if err != nil {
		return nil, nil, fmt.Errorf("join multicast %q: %w", group, err)
	}
	return conn, gaddr, nil
}
