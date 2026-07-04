package roster

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/netbirdio/netbird/monotime"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testAuthority(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func sampleRoster(exp time.Time) *Roster {
	return &Roster{
		Version:   CurrentVersion,
		Mission:   "alpha",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: exp.Unix(),
		Peers: []Peer{
			{WGPubKey: "peerA", IP: "100.64.0.2", AllowedIPs: []string{"100.64.0.2/32"}},
			{WGPubKey: "peerB", IP: "100.64.0.3", AllowedIPs: []string{"100.64.0.3/32"}},
		},
	}
}

func TestSignAndVerify(t *testing.T) {
	anchor, priv := testAuthority(t)
	r := sampleRoster(time.Now().Add(time.Hour))
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := r.VerifySignature(anchor); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestVerify_TamperedFails(t *testing.T) {
	anchor, priv := testAuthority(t)
	r := sampleRoster(time.Now().Add(time.Hour))
	_ = r.Sign(priv)

	r.Peers[0].IP = "100.64.0.99" // tamper after signing
	if err := r.VerifySignature(anchor); err == nil {
		t.Fatal("expected signature failure after tamper")
	}
}

func TestVerify_WrongAnchorFails(t *testing.T) {
	_, priv := testAuthority(t)
	otherAnchor, _ := testAuthority(t)
	r := sampleRoster(time.Now().Add(time.Hour))
	_ = r.Sign(priv)
	if err := r.VerifySignature(otherAnchor); err == nil {
		t.Fatal("expected failure verifying against wrong anchor")
	}
}

func TestValidate_Expiry(t *testing.T) {
	anchor, priv := testAuthority(t)

	// Fresh roster.
	fresh := sampleRoster(time.Now().Add(time.Hour))
	_ = fresh.Sign(priv)
	if err := fresh.Validate(anchor, ValidationOptions{}); err != nil {
		t.Fatalf("fresh roster should validate: %v", err)
	}

	// Expired beyond grace.
	expired := sampleRoster(time.Now().Add(-time.Hour))
	_ = expired.Sign(priv)
	if err := expired.Validate(anchor, ValidationOptions{}); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	// Expired but within grace.
	if err := expired.Validate(anchor, ValidationOptions{Grace: 2 * time.Hour}); err != nil {
		t.Fatalf("within grace should validate: %v", err)
	}

	// AllowExpired bypasses freshness (last-known-good).
	if err := expired.Validate(anchor, ValidationOptions{AllowExpired: true}); err != nil {
		t.Fatalf("AllowExpired should validate a signed-but-stale roster: %v", err)
	}
}

func TestValidate_NotYetValid(t *testing.T) {
	anchor, priv := testAuthority(t)
	r := sampleRoster(time.Now().Add(2 * time.Hour))
	r.IssuedAt = time.Now().Add(time.Hour).Unix() // future
	_ = r.Sign(priv)
	if err := r.Validate(anchor, ValidationOptions{}); err != ErrNotYetValid {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

func TestValidate_ExpiredStillNeedsSignature(t *testing.T) {
	anchor, priv := testAuthority(t)
	r := sampleRoster(time.Now().Add(-time.Hour))
	_ = r.Sign(priv)
	r.Peers = append(r.Peers, Peer{WGPubKey: "intruder", IP: "100.64.0.9"}) // tamper
	if err := r.Validate(anchor, ValidationOptions{AllowExpired: true}); err == nil {
		t.Fatal("AllowExpired must still reject a bad signature")
	}
}

func TestBeaconKeyDerivation_Deterministic(t *testing.T) {
	wg, _ := wgtypes.GenerateKey()
	p1, pub1, err := DeriveBeaconKey(wg)
	if err != nil {
		t.Fatalf("DeriveBeaconKey: %v", err)
	}
	p2, pub2, _ := DeriveBeaconKey(wg)
	if string(p1) != string(p2) || string(pub1) != string(pub2) {
		t.Fatal("beacon key derivation must be deterministic for the same WG key")
	}

	other, _ := wgtypes.GenerateKey()
	_, pubOther, _ := DeriveBeaconKey(other)
	if string(pub1) == string(pubOther) {
		t.Fatal("different WG keys must derive different beacon keys")
	}
}

func TestBeacon_SignVerifyAgainstRoster(t *testing.T) {
	anchor, authPriv := testAuthority(t)
	wg, _ := wgtypes.GenerateKey()
	beaconPriv, beaconPub, _ := DeriveBeaconKey(wg)

	r := &Roster{
		Version:   CurrentVersion,
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Peers: []Peer{
			{WGPubKey: "node1", IP: "100.64.0.5", BeaconPubKey: beaconPub},
		},
	}
	_ = r.Sign(authPriv)
	if err := r.Validate(anchor, ValidationOptions{}); err != nil {
		t.Fatalf("roster validate: %v", err)
	}

	b := &Beacon{WGPubKey: "node1", Endpoint: "10.0.0.5:51820", Timestamp: time.Now().Unix()}
	if err := SignBeacon(b, beaconPriv); err != nil {
		t.Fatalf("SignBeacon: %v", err)
	}
	if err := VerifyBeaconAgainstRoster(b, r); err != nil {
		t.Fatalf("VerifyBeaconAgainstRoster: %v", err)
	}

	// Tampered endpoint fails.
	b.Endpoint = "10.0.0.6:51820"
	if err := VerifyBeaconAgainstRoster(b, r); err == nil {
		t.Fatal("tampered beacon should fail verification")
	}
}

func TestBeacon_UnknownPeer(t *testing.T) {
	wg, _ := wgtypes.GenerateKey()
	beaconPriv, _, _ := DeriveBeaconKey(wg)
	r := &Roster{Version: CurrentVersion, Peers: []Peer{{WGPubKey: "known"}}}

	b := &Beacon{WGPubKey: "stranger", Endpoint: "x:1", Timestamp: 1}
	_ = SignBeacon(b, beaconPriv)
	if err := VerifyBeaconAgainstRoster(b, r); err != ErrUnknownPeer {
		t.Fatalf("expected ErrUnknownPeer, got %v", err)
	}
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	_, priv := testAuthority(t)
	r := sampleRoster(time.Now().Add(time.Hour))
	_ = r.Sign(priv)

	data, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Peers) != 2 || got.Peers[0].WGPubKey != "peerA" {
		t.Fatalf("round-trip lost data: %+v", got)
	}
}

func TestUnmarshal_RejectsUnknownFields(t *testing.T) {
	if _, err := Unmarshal([]byte(`{"version":1,"peers":[],"bogus":true}`)); err == nil {
		t.Fatal("expected error on unknown fields")
	}
}

func TestFreshnessTracker_MonotonicAnchored(t *testing.T) {
	anchor := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := &FreshnessTracker{
		refWall: anchor,
		refMono: monotime.Now(),
		since:   func(monotime.Time) time.Duration { return 90 * time.Second }, // injected elapsed
	}
	got := tr.Now()
	want := anchor.Add(90 * time.Second)
	if !got.Equal(want) {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestValidateMonotonic_UsesTrackerClock(t *testing.T) {
	pub, priv := testAuthority(t)
	// Roster expires 1 minute after the anchor.
	anchor := time.Unix(1_000_000, 0)
	r := &Roster{
		Version:   CurrentVersion,
		IssuedAt:  anchor.Add(-time.Minute).Unix(),
		ExpiresAt: anchor.Add(time.Minute).Unix(),
		Peers:     []Peer{{WGPubKey: "p", IP: "100.64.0.2"}},
	}
	_ = r.Sign(priv)

	// Tracker at anchor + 30s (elapsed injected) -> still fresh.
	trFresh := &FreshnessTracker{refWall: anchor, refMono: monotime.Now(), since: func(monotime.Time) time.Duration { return 30 * time.Second }}
	if err := r.ValidateMonotonic(pub, trFresh, 0); err != nil {
		t.Fatalf("expected fresh via monotonic clock, got %v", err)
	}

	// Tracker at anchor + 5min -> expired, but 10min grace saves it.
	trStale := &FreshnessTracker{refWall: anchor, refMono: monotime.Now(), since: func(monotime.Time) time.Duration { return 5 * time.Minute }}
	if err := r.ValidateMonotonic(pub, trStale, 0); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if err := r.ValidateMonotonic(pub, trStale, 10*time.Minute); err != nil {
		t.Fatalf("expected grace to save it, got %v", err)
	}
}

func TestStore_AcceptLoad_LastKnownGood(t *testing.T) {
	anchor, priv := testAuthority(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")

	// Accept a fresh roster.
	fresh := sampleRoster(time.Now().Add(time.Hour))
	_ = fresh.Sign(priv)
	st := NewStore(path, anchor, time.Minute, time.Now())
	if err := st.Accept(fresh); err != nil {
		t.Fatalf("Accept fresh: %v", err)
	}

	// Load -> fresh, not expired.
	got, expired, err := st.Load()
	if err != nil || expired || got == nil || len(got.Peers) != 2 {
		t.Fatalf("Load fresh: got=%v expired=%v err=%v", got, expired, err)
	}

	// Overwrite the cache with a stale-but-signed roster; Load returns it flagged expired.
	stale := sampleRoster(time.Now().Add(-time.Hour))
	_ = stale.Sign(priv)
	if err := st.persist(stale); err != nil {
		t.Fatalf("persist stale: %v", err)
	}
	got, expired, err = st.Load()
	if err != nil {
		t.Fatalf("Load stale: %v", err)
	}
	if !expired || got == nil {
		t.Fatalf("expected last-known-good (expired=true), got expired=%v got=%v", expired, got)
	}
}

func TestStore_Accept_RejectsExpired(t *testing.T) {
	anchor, priv := testAuthority(t)
	st := NewStore(filepath.Join(t.TempDir(), "r.json"), anchor, 0, time.Now())
	stale := sampleRoster(time.Now().Add(-time.Hour))
	_ = stale.Sign(priv)
	if err := st.Accept(stale); err != ErrExpired {
		t.Fatalf("Accept should reject expired (beyond grace), got %v", err)
	}
}
