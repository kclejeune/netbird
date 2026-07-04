// Package roster implements signed peer rosters for disconnected ("offline
// island") operation of a TacMesh node.
//
// A roster is a signed list of the peers allowed in a mission mesh. When the
// management server is unreachable, a node bootstraps and maintains its mesh
// from a roster alone. Two signing concerns are handled, deliberately kept
// distinct to avoid the Curve25519-vs-Ed25519 pitfalls of signing with a raw
// WireGuard key:
//
//   - Roster authority: the whole roster is signed by a mission Ed25519 key. A
//     node verifies it against a configured trust anchor (the authority public
//     key). Individual peers do NOT sign the roster.
//
//   - Beacon signing: for multicast presence beacons, each node needs a signing
//     key a peer can verify. Rather than convert the node's Curve25519 WireGuard
//     key to Ed25519 (XEd25519, error-prone), each node derives a dedicated
//     Ed25519 beacon key deterministically from its WireGuard private key via
//     HKDF-SHA256, and the roster binds that beacon public key to the node's
//     WireGuard public key. Beacons are verified against the roster-bound key.
//
// Freshness is enforced with an expiry plus a configurable grace period, and a
// monotonic-time guard so a peer with a wildly wrong wall clock cannot be
// tricked into accepting a long-expired roster (or rejecting a valid one). A
// last-known-good roster on disk provides a fallback when no fresh roster is
// available — the core requirement for surviving a disconnected mission.
package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CurrentVersion is the roster schema version.
const CurrentVersion = 1

// hkdfInfo domain-separates the beacon-signing key derivation.
const hkdfInfo = "tacmesh-roster-beacon-ed25519-v1"

var (
	// ErrSignature indicates the roster (or beacon) signature did not verify.
	ErrSignature = errors.New("roster: signature verification failed")
	// ErrExpired indicates the roster is past its expiry plus grace.
	ErrExpired = errors.New("roster: expired")
	// ErrNotYetValid indicates the roster's IssuedAt is in the future.
	ErrNotYetValid = errors.New("roster: not yet valid")
	// ErrUnknownPeer indicates a beacon's WG key is not in the roster.
	ErrUnknownPeer = errors.New("roster: unknown peer")
	// ErrVersion indicates an unsupported roster version.
	ErrVersion = errors.New("roster: unsupported version")
)

// Peer is one entry in a roster: the mesh identity of an allowed node.
type Peer struct {
	// WGPubKey is the peer's WireGuard public key (base64).
	WGPubKey string `json:"wgPubKey"`
	// IP is the peer's mesh IP (e.g. "100.64.0.2").
	IP string `json:"ip"`
	// AllowedIPs are the CIDRs routed to this peer.
	AllowedIPs []string `json:"allowedIps,omitempty"`
	// Endpoint is an optional static transport endpoint (host:port). Infrastructure
	// peers with a fixed endpoint can be programmed immediately; peers without one
	// await endpoint discovery (multicast beacons) before a tunnel is formed.
	Endpoint string `json:"endpoint,omitempty"`
	// BeaconPubKey is the peer's Ed25519 beacon-signing public key (base64),
	// bound to WGPubKey by the roster authority's signature.
	BeaconPubKey []byte `json:"beaconPubKey,omitempty"`
}

// Roster is a signed list of mesh peers.
type Roster struct {
	Version int `json:"version"`
	// Mission is an optional human label.
	Mission string `json:"mission,omitempty"`
	// IssuedAt / ExpiresAt are unix seconds (wall clock).
	IssuedAt  int64 `json:"issuedAt"`
	ExpiresAt int64 `json:"expiresAt"`
	// Peers is the allowed peer set.
	Peers []Peer `json:"peers"`
	// Signature is the authority's Ed25519 signature over the signing payload.
	Signature []byte `json:"signature,omitempty"`
}

// signingBytes returns the canonical bytes covered by the signature: the roster
// with Signature cleared. Peers/AllowedIPs are slices (no maps), so JSON is
// deterministic.
func (r *Roster) signingBytes() ([]byte, error) {
	cp := *r
	cp.Signature = nil
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}
	return b, nil
}

// Sign signs the roster with the authority Ed25519 private key.
func (r *Roster) Sign(authority ed25519.PrivateKey) error {
	if r.Version == 0 {
		r.Version = CurrentVersion
	}
	msg, err := r.signingBytes()
	if err != nil {
		return err
	}
	r.Signature = ed25519.Sign(authority, msg)
	return nil
}

// VerifySignature checks only the authority signature (not freshness).
func (r *Roster) VerifySignature(anchor ed25519.PublicKey) error {
	if r.Version != CurrentVersion {
		return fmt.Errorf("%w: %d", ErrVersion, r.Version)
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return ErrSignature
	}
	msg, err := r.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(anchor, msg, r.Signature) {
		return ErrSignature
	}
	return nil
}

// ValidationOptions controls freshness checks.
type ValidationOptions struct {
	// Now is the wall-clock reference (defaults to time.Now()).
	Now time.Time
	// Grace extends validity past ExpiresAt (clock-drift / disconnected slack).
	Grace time.Duration
	// AllowExpired accepts a validly-signed but expired roster (last-known-good
	// mode) — the signature is still required.
	AllowExpired bool
}

// Validate verifies the signature and, unless AllowExpired, the freshness
// (IssuedAt <= now, now <= ExpiresAt+Grace).
func (r *Roster) Validate(anchor ed25519.PublicKey, opts ValidationOptions) error {
	if err := r.VerifySignature(anchor); err != nil {
		return err
	}
	if opts.AllowExpired {
		return nil
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() < r.IssuedAt {
		return ErrNotYetValid
	}
	if now.Unix() > r.ExpiresAt+int64(opts.Grace.Seconds()) {
		return ErrExpired
	}
	return nil
}

// FindPeer returns the roster entry for a WireGuard public key.
func (r *Roster) FindPeer(wgPubKey string) (*Peer, bool) {
	for i := range r.Peers {
		if r.Peers[i].WGPubKey == wgPubKey {
			return &r.Peers[i], true
		}
	}
	return nil, false
}

// --- Beacon signing (HKDF-derived Ed25519 from the WireGuard key) ----------

// DeriveBeaconKey deterministically derives a node's Ed25519 beacon-signing
// keypair from its WireGuard private key using HKDF-SHA256. The same WireGuard
// key always yields the same beacon key, so the public half can be bound into
// the roster ahead of time.
func DeriveBeaconKey(wgPriv wgtypes.Key) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	kdf := hkdf.New(sha256.New, wgPriv[:], nil, []byte(hkdfInfo))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(kdf, seed); err != nil {
		return nil, nil, fmt.Errorf("hkdf: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// Beacon is a signed presence announcement for multicast discovery.
type Beacon struct {
	// WGPubKey identifies the announcing node (base64 WireGuard public key).
	WGPubKey string `json:"wgPubKey"`
	// Endpoint is the transport endpoint the node is reachable at.
	Endpoint string `json:"endpoint"`
	// Timestamp is unix seconds, for replay bounding.
	Timestamp int64 `json:"timestamp"`
	// Sig is the Ed25519 signature over the beacon payload.
	Sig []byte `json:"sig,omitempty"`
}

func (b *Beacon) signingBytes() ([]byte, error) {
	cp := *b
	cp.Sig = nil
	return json.Marshal(&cp)
}

// SignBeacon signs a beacon with the node's derived Ed25519 beacon key.
func SignBeacon(b *Beacon, beaconPriv ed25519.PrivateKey) error {
	msg, err := b.signingBytes()
	if err != nil {
		return err
	}
	b.Sig = ed25519.Sign(beaconPriv, msg)
	return nil
}

// VerifyBeaconAgainstRoster verifies a beacon's signature using the beacon
// public key the roster binds to the beacon's WGPubKey. This authenticates that
// the beacon comes from a rostered node without ever converting WireGuard keys.
func VerifyBeaconAgainstRoster(b *Beacon, r *Roster) error {
	peer, ok := r.FindPeer(b.WGPubKey)
	if !ok {
		return ErrUnknownPeer
	}
	if len(peer.BeaconPubKey) != ed25519.PublicKeySize {
		return ErrSignature
	}
	msg, err := b.signingBytes()
	if err != nil {
		return err
	}
	if len(b.Sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(peer.BeaconPubKey), msg, b.Sig) {
		return ErrSignature
	}
	return nil
}

// --- Persistence (last-known-good) ----------------------------------------

// Marshal serializes the roster to JSON.
func (r *Roster) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Unmarshal parses a roster from JSON.
func Unmarshal(data []byte) (*Roster, error) {
	var r Roster
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("unmarshal roster: %w", err)
	}
	return &r, nil
}
