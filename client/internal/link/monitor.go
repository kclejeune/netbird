package link

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultMonitorInterval is the default link-health refresh period.
const DefaultMonitorInterval = 5 * time.Second

// Neighbour is a proto/babel-independent view of a routing neighbour on an
// interface. The engine adapts babel neighbours into this type so the link
// package stays free of a babel (and thus gvisor) dependency and is unit
// testable with fakes.
type Neighbour struct {
	Interface string
	RTTMs     uint32
	Cost      uint32
	Up        bool
}

// NeighbourFunc returns the current routing neighbours (e.g. from babeld).
// May be nil.
type NeighbourFunc func() ([]Neighbour, error)

// LivenessFunc reports whether a non-primary interface currently looks alive and
// an optional latency hint, used when no neighbour data is available (e.g. babel
// disabled, static mesh peers). May be nil.
type LivenessFunc func(ifaceName string) (up bool, latencyMs uint32)

// Monitor periodically refreshes each link's LinkState in the Manager from live
// signals. It is deliberately conservative about the primary link: the primary
// wraps the local WireGuard interface, which is up as soon as it exists, so the
// Monitor never marks it down (a missing per-peer handshake does not mean the
// local interface is down). Mesh links are driven up/down by neighbour presence
// (or the liveness fallback), which is what path selection should react to.
type Monitor struct {
	mgr        *Manager
	interval   time.Duration
	neighbours NeighbourFunc
	liveness   LivenessFunc
	now        func() time.Time // injectable for tests
}

// NewMonitor builds a link-health Monitor. interval <= 0 uses the default.
func NewMonitor(mgr *Manager, interval time.Duration, neighbours NeighbourFunc, liveness LivenessFunc) *Monitor {
	if interval <= 0 {
		interval = DefaultMonitorInterval
	}
	return &Monitor{
		mgr:        mgr,
		interval:   interval,
		neighbours: neighbours,
		liveness:   liveness,
		now:        time.Now,
	}
}

// Run refreshes link health every interval until ctx is cancelled. It performs
// one immediate pass before the first tick so state is populated promptly.
func (mo *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(mo.interval)
	defer t.Stop()

	mo.Tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mo.Tick()
		}
	}
}

// Tick performs a single health-refresh pass. Exported for tests.
func (mo *Monitor) Tick() {
	if mo.mgr == nil {
		return
	}

	byIface := mo.aggregateNeighbours()
	now := mo.now()

	for _, l := range mo.mgr.Links() {
		if l.Iface == nil {
			continue
		}
		ifName := l.Iface.Name()

		// Primary link: always up; annotate latency if a neighbour reports one.
		if l.ID == primaryLinkID {
			st := l.State()
			st.Up = true
			st.LastProbe = now
			if n, ok := byIface[ifName]; ok {
				st.LatencyMs = n.RTTMs
			}
			l.UpdateState(st)
			continue
		}

		// Mesh link: neighbour data wins; otherwise fall back to liveness.
		st := LinkState{LastProbe: now}
		if n, ok := byIface[ifName]; ok && n.Up {
			st.Up = true
			st.LatencyMs = n.RTTMs
		} else if mo.liveness != nil {
			st.Up, st.LatencyMs = mo.liveness(ifName)
		}
		l.UpdateState(st)
	}
}

// aggregateNeighbours collapses per-neighbour data to per-interface: up if any
// neighbour on the interface is up, latency = min RTT among up neighbours.
func (mo *Monitor) aggregateNeighbours() map[string]Neighbour {
	out := map[string]Neighbour{}
	if mo.neighbours == nil {
		return out
	}
	nbs, err := mo.neighbours()
	if err != nil {
		log.Debugf("link monitor: neighbour query failed: %v", err)
		return out
	}
	for _, n := range nbs {
		if !n.Up {
			continue
		}
		cur, ok := out[n.Interface]
		if !ok {
			out[n.Interface] = n
			continue
		}
		if n.RTTMs > 0 && (cur.RTTMs == 0 || n.RTTMs < cur.RTTMs) {
			cur.RTTMs = n.RTTMs
		}
		cur.Up = true
		out[n.Interface] = cur
	}
	return out
}
