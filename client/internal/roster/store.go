package roster

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

// Store loads and persists the last-known-good roster for disconnected
// operation. On load it prefers a fresh, validly-signed roster; if the freshest
// roster is expired (beyond grace) it falls back to the most recent validly
// signed roster it has ("last known good"), which is the behavior a mission
// needs when the management/authority is unreachable and clocks have drifted.
type Store struct {
	// path is where the accepted last-known-good roster is cached.
	path string
	// anchor is the authority Ed25519 public key (trust anchor).
	anchor ed25519.PublicKey
	// grace extends validity past ExpiresAt.
	grace time.Duration
	// tracker provides a monotonic-anchored clock (optional).
	tracker *FreshnessTracker
}

// NewStore creates a roster store persisting to cachePath, verifying against
// anchor, applying the given grace period. trustedNow anchors the monotonic
// freshness tracker (pass the most trusted wall-clock time available, e.g. the
// last management contact, or time.Now() at startup).
func NewStore(cachePath string, anchor ed25519.PublicKey, grace time.Duration, trustedNow time.Time) *Store {
	return &Store{
		path:    cachePath,
		anchor:  anchor,
		grace:   grace,
		tracker: NewFreshnessTracker(trustedNow),
	}
}

// now returns the monotonic-anchored effective time.
func (s *Store) now() time.Time {
	if s.tracker != nil {
		return s.tracker.Now()
	}
	return time.Now()
}

// Accept validates a freshly-received roster and, if valid and fresh, persists
// it as the new last-known-good. A validly-signed but expired roster is
// rejected here (it is only used as a fallback via Load).
func (s *Store) Accept(r *Roster) error {
	if err := r.Validate(s.anchor, ValidationOptions{Now: s.now(), Grace: s.grace}); err != nil {
		return err
	}
	return s.persist(r)
}

// Load returns the best roster available: the cached last-known-good, validated
// for signature. If it is fresh (within expiry+grace) it is returned with
// expired=false; if it is signature-valid but stale, it is still returned with
// expired=true so the caller can decide to run in degraded last-known-good mode
// rather than deny all. A missing or signature-invalid cache is an error.
func (s *Store) Load() (r *Roster, expired bool, err error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, false, fmt.Errorf("read roster cache: %w", err)
	}
	r, err = Unmarshal(data)
	if err != nil {
		return nil, false, err
	}
	// Fresh check first.
	if verr := r.Validate(s.anchor, ValidationOptions{Now: s.now(), Grace: s.grace}); verr == nil {
		return r, false, nil
	}
	// Signature must still hold for last-known-good use.
	if verr := r.Validate(s.anchor, ValidationOptions{AllowExpired: true}); verr != nil {
		return nil, false, verr
	}
	log.Warnf("roster: using last-known-good (expired at %s); running in degraded offline mode",
		time.Unix(r.ExpiresAt, 0).UTC().Format(time.RFC3339))
	return r, true, nil
}

func (s *Store) persist(r *Roster) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create roster dir: %w", err)
	}
	data, err := r.Marshal()
	if err != nil {
		return err
	}
	if err := util.WriteBytesWithRestrictedPermission(context.Background(), s.path, data); err != nil {
		return fmt.Errorf("write roster cache: %w", err)
	}
	return nil
}
