package roster

import (
	"time"

	"github.com/netbirdio/netbird/monotime"
)

// FreshnessTracker derives an "effective now" that advances with the monotonic
// clock from a trusted wall-clock anchor. It is used so a node whose wall clock
// is wrong (no NTP in the field) cannot be tricked into accepting a long-expired
// roster or rejecting a fresh one: expiry is measured as monotonic time elapsed
// since a trusted reference (e.g. the moment a valid roster was last accepted,
// or last management contact) rather than trusting the wall clock directly.
type FreshnessTracker struct {
	refWall time.Time
	refMono monotime.Time
	since   func(monotime.Time) time.Duration // injectable for tests
}

// NewFreshnessTracker anchors the tracker at trustedNow (a wall-clock time the
// caller trusts) and the current monotonic instant.
func NewFreshnessTracker(trustedNow time.Time) *FreshnessTracker {
	return &FreshnessTracker{
		refWall: trustedNow,
		refMono: monotime.Now(),
		since:   monotime.Since,
	}
}

// Now returns trustedAnchor + (monotonic time elapsed since the anchor).
func (f *FreshnessTracker) Now() time.Time {
	return f.refWall.Add(f.since(f.refMono))
}

// ValidateMonotonic validates a roster using the tracker's monotonic-anchored
// clock instead of the wall clock, applying the given grace period.
func (r *Roster) ValidateMonotonic(anchor []byte, tracker *FreshnessTracker, grace time.Duration) error {
	return r.Validate(anchor, ValidationOptions{Now: tracker.Now(), Grace: grace})
}
