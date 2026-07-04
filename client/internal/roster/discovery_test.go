package roster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// --- in-memory multicast bus --------------------------------------------------

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type memPkt struct {
	data []byte
	src  net.Addr
}

type memBus struct {
	mu    sync.Mutex
	conns []*memConn
}

func (b *memBus) join(name string) *memConn {
	c := &memConn{bus: b, addr: memAddr(name), inbox: make(chan memPkt, 64), closed: make(chan struct{})}
	b.mu.Lock()
	b.conns = append(b.conns, c)
	b.mu.Unlock()
	return c
}

type memConn struct {
	bus    *memBus
	addr   net.Addr
	inbox  chan memPkt
	closed chan struct{}

	mu       sync.Mutex
	deadline time.Time
}

func (c *memConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	c.bus.mu.Lock()
	targets := append([]*memConn(nil), c.bus.conns...)
	c.bus.mu.Unlock()
	for _, t := range targets {
		if t == c {
			continue // deliver to others (self-skip is also enforced in handle)
		}
		select {
		case t.inbox <- memPkt{data: cp, src: c.addr}:
		default: // drop if full — mirrors lossy multicast
		}
	}
	return len(p), nil
}

func (c *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, timeoutError{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-c.inbox:
		return copy(p, pkt.data), pkt.src, nil
	case <-timer:
		return 0, nil, timeoutError{}
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *memConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

// --- helpers ------------------------------------------------------------------

type node struct {
	wgPub      string
	beaconPub  ed25519.PublicKey
	beaconPriv ed25519.PrivateKey
}

func makeNode(t *testing.T, name string) node {
	t.Helper()
	wg, _ := wgtypes.GenerateKey()
	priv, pub, err := DeriveBeaconKey(wg)
	if err != nil {
		t.Fatalf("DeriveBeaconKey: %v", err)
	}
	return node{wgPub: name, beaconPub: pub, beaconPriv: priv}
}

func rosterFor(t *testing.T, nodes ...node) *Roster {
	t.Helper()
	_, authPriv := testAuthority(t)
	r := &Roster{
		Version:   CurrentVersion,
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	for _, n := range nodes {
		r.Peers = append(r.Peers, Peer{WGPubKey: n.wgPub, IP: "100.64.0.2", BeaconPubKey: n.beaconPub})
	}
	if err := r.Sign(authPriv); err != nil {
		t.Fatalf("sign roster: %v", err)
	}
	return r
}

// --- integration: two nodes discover each other over the bus ------------------

func TestDiscovery_EndToEnd(t *testing.T) {
	a := makeNode(t, "nodeA")
	b := makeNode(t, "nodeB")
	r := rosterFor(t, a, b)

	bus := &memBus{}
	connA := bus.join("A")
	connB := bus.join("B")

	got := make(chan DiscoveredPeer, 4)
	// A announces its endpoint; B is receive-only and should discover A.
	da := NewDiscovery(DiscoveryConfig{
		Conn: connA, Group: memAddr("group"), SelfWGPubKey: a.wgPub,
		SelfEndpoint: "10.0.0.1:51820", BeaconPriv: a.beaconPriv, Roster: r, Interval: 15 * time.Millisecond,
	})
	db := NewDiscovery(DiscoveryConfig{
		Conn: connB, Group: memAddr("group"), SelfWGPubKey: b.wgPub,
		BeaconPriv: b.beaconPriv, Roster: r, Interval: 15 * time.Millisecond,
		OnPeer: func(p DiscoveredPeer) { got <- p },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go da.Run(ctx)
	go db.Run(ctx)

	select {
	case p := <-got:
		if p.Peer.WGPubKey != "nodeA" || p.Endpoint != "10.0.0.1:51820" {
			t.Fatalf("unexpected discovery: %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for discovery")
	}
}

// --- deterministic handle() cases ---------------------------------------------

func newRxDiscovery(self string, r *Roster, onPeer func(DiscoveredPeer)) *Discovery {
	return NewDiscovery(DiscoveryConfig{
		Conn: nil, Group: memAddr("g"), SelfWGPubKey: self, Roster: r, OnPeer: onPeer,
	})
}

func signedBeaconBytes(t *testing.T, n node, endpoint string, ts int64) []byte {
	t.Helper()
	bc := Beacon{WGPubKey: n.wgPub, Endpoint: endpoint, Timestamp: ts}
	if err := SignBeacon(&bc, n.beaconPriv); err != nil {
		t.Fatalf("sign beacon: %v", err)
	}
	data, _ := json.Marshal(&bc)
	return data
}

func TestDiscovery_Handle_AuthAndDedup(t *testing.T) {
	peer := makeNode(t, "peer")
	me := makeNode(t, "me")
	r := rosterFor(t, peer, me)

	var mu sync.Mutex
	var calls []DiscoveredPeer
	d := newRxDiscovery("me", r, func(p DiscoveredPeer) {
		mu.Lock()
		calls = append(calls, p)
		mu.Unlock()
	})

	now := time.Now().Unix()

	// First beacon -> delivered.
	d.handle(signedBeaconBytes(t, peer, "10.0.0.2:51820", now), memAddr("src"))
	// Replay (same ts) -> dropped.
	d.handle(signedBeaconBytes(t, peer, "10.0.0.2:51820", now), memAddr("src"))
	// Newer ts, same endpoint -> dropped (endpoint unchanged).
	d.handle(signedBeaconBytes(t, peer, "10.0.0.2:51820", now+1), memAddr("src"))
	// Newer ts, changed endpoint -> delivered.
	d.handle(signedBeaconBytes(t, peer, "10.0.0.9:51820", now+2), memAddr("src"))

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("expected 2 deliveries (first + endpoint change), got %d: %+v", len(calls), calls)
	}
	if calls[0].Endpoint != "10.0.0.2:51820" || calls[1].Endpoint != "10.0.0.9:51820" {
		t.Fatalf("wrong endpoints: %+v", calls)
	}
}

func TestDiscovery_Handle_RejectsUnknownAndBadSig(t *testing.T) {
	peer := makeNode(t, "peer")
	me := makeNode(t, "me")
	stranger := makeNode(t, "stranger")
	r := rosterFor(t, peer, me) // stranger NOT in roster

	fired := 0
	d := newRxDiscovery("me", r, func(DiscoveredPeer) { fired++ })
	now := time.Now().Unix()

	// Unknown peer (valid self-sig, but not rostered) -> rejected.
	d.handle(signedBeaconBytes(t, stranger, "10.0.0.3:1", now), memAddr("s"))

	// Rostered peer but signature tampered -> rejected.
	bad := signedBeaconBytes(t, peer, "10.0.0.2:1", now)
	bad[len(bad)-5] ^= 0xFF
	d.handle(bad, memAddr("s"))

	// Our own beacon -> ignored.
	d.handle(signedBeaconBytes(t, me, "10.0.0.9:1", now), memAddr("s"))

	if fired != 0 {
		t.Fatalf("expected no deliveries, got %d", fired)
	}
}

func TestDiscovery_Handle_TimestampSkew(t *testing.T) {
	peer := makeNode(t, "peer")
	me := makeNode(t, "me")
	r := rosterFor(t, peer, me)

	fired := 0
	d := newRxDiscovery("me", r, func(DiscoveredPeer) { fired++ })
	d.maxSkew = 30 * time.Second

	// Beacon far in the past -> rejected.
	d.handle(signedBeaconBytes(t, peer, "10.0.0.2:1", time.Now().Add(-time.Hour).Unix()), memAddr("s"))
	// Beacon far in the future -> rejected.
	d.handle(signedBeaconBytes(t, peer, "10.0.0.2:1", time.Now().Add(time.Hour).Unix()), memAddr("s"))

	if fired != 0 {
		t.Fatalf("expected skewed beacons rejected, got %d deliveries", fired)
	}
}
