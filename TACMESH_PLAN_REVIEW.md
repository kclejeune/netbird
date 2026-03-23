# TacMesh Implementation Plan Review

## Context

The user provided a detailed 8-stage, 17-week implementation plan for "TacMesh" — a tactical mesh network built by forking NetBird and integrating Babel routing, multi-link transport, and FIPS-compliant encryption. This review identifies weaknesses in the plan based on actual codebase analysis and proposes a revised implementation approach.

---

## Weakness Analysis

### Critical Issues

#### C1. Single-Interface Refactoring is Catastrophically Underestimated
The plan's Stage 3 proposes replacing `wgInterface WGIface` with `map[string]*iface.WGIface` as if it's a contained change. In reality, the single-interface assumption is load-bearing throughout the entire client:

- **`Engine.wgInterface`** (`client/internal/engine.go:189`): referenced across the 2000+ line engine file in peer creation, route management, firewall setup, DNS, and lifecycle monitoring.
- **`Engine.udpMux`** (line 191): a single UDP mux for ICE candidate gathering — multi-link needs one per interface.
- **`PeerStore`** (`client/internal/peerstore/store.go`): maps `pubKey -> *peer.Conn` where each `Conn` holds a single `WgConfig`. Multi-link means each peer needs connections across multiple interfaces.
- **`ConnMgr`** (`client/internal/conn_mgr.go`): stores a single `iface` field for lazy connection setup.
- **`WorkerICE`** (`client/internal/peer/worker_ice.go`): ICE candidate gathering is per-engine, not per-link.
- **Route Watcher** (`client/internal/routemanager/client/client.go`): `getBestRouteFromStatuses()` scores peers without interface awareness.
- **Firewall, ACL, DNS** all initialized from the single interface context.

**Impact**: 6-10 week schedule slip. The plan allocates 3 weeks for Stage 3; the actual refactoring is closer to 8-12 weeks.

**Mitigation**: Introduce a `LinkManager` abstraction layer between Engine and individual WGIface instances. Engine interacts only with LinkManager. Design this before writing any multi-link code.

#### C2. FIPS Compliance is a Protocol-Breaking Change, Not a Late-Stage Audit
The plan treats FIPS as a Stage 5 concern (weeks 11-13). The primary non-FIPS crypto is NaCl box (`encryption/encryption.go` using `golang.org/x/crypto/nacl/box` — Curve25519 + XSalsa20-Poly1305), which encrypts **every single management and signal RPC**:

- `management.proto`: `Login`, `Sync`, `SyncMeta`, `Logout`, `Job`, `CreateExpose`, `RenewExpose`, `StopExpose` — all use `EncryptedMessage`.
- `signalexchange.proto`: `Send` and `ConnectStream` — both use `EncryptedMessage`.

Replacing NaCl with FIPS-approved crypto (e.g., AES-256-GCM + ECDH-P384) changes the wire protocol. The fork cannot interoperate with stock NetBird servers. Discovering this at week 11 after building 4 stages on the non-FIPS protocol is a project-killing risk.

**Mitigation**: Move FIPS to Stage 0. Design a `crypto/envelope` abstraction supporting both NaCl (backward compat during dev) and FIPS-approved algorithms. All subsequent stages build on the FIPS-ready envelope.

#### C3. QUIC-over-WireGuard Creates an Unworkable Protocol Stack
The proposed architecture: `App -> QUIC(AES-256-GCM) -> TUN -> WireGuard(ChaCha20-Poly1305) -> UDP -> Wire`.

Problems:
- **Double encryption** with no security benefit — WireGuard already provides authenticated encryption.
- **Overhead underestimated**: QUIC adds ~60 bytes (header + framing + AEAD tag), not the claimed 30 bytes. Combined with WireGuard's 60-byte overhead, the effective payload on a 1500-byte link drops to ~1380 — and to ~1250 on Silvus (1280 MTU link), which is below IPv6 minimum after Babel overhead.
- **TCP-over-QUIC-over-WireGuard**: Competing congestion controllers at two layers is a known anti-pattern causing throughput collapse.
- **N x M session explosion**: N peers x M links = N*M QUIC connections to manage.
- **`crypto/internal/fips140`** is a Go-internal package, not importable by external code.

**Mitigation**: Abandon QUIC-over-WireGuard. Two viable alternatives:
1. Replace WireGuard's userspace crypto module with a FIPS-approved AEAD (AES-256-GCM via Go 1.24+ FIPS module) at the wireguard-go layer.
2. Use the existing relay QUIC transport (`relay/server/listener/quic/`) as the primary transport *instead of* WireGuard, eliminating double encryption.

#### C4. Signal and Management Protocol Changes Are Completely Unaddressed
The plan has no discussion of how management or signal protocols must change for multi-link:

- **`RemotePeerConfig`** in `management.proto` sends a single `wgPubKey` and single `allowedIps` list per peer. No per-link endpoint configuration.
- **Signal ICE exchange** operates on a single peer-to-peer channel with no link identifier.

Without protocol extensions, the management server cannot distribute link-specific config and the signal server cannot coordinate per-link ICE.

**Mitigation**: Design proto extensions early. Add `LinkConfig` message with link-specific endpoint info, MTU, and priority. Extend `RemotePeerConfig` with `repeated LinkConfig links`. Extend signal protocol with link identifier in ICE offer/answer.

---

### High-Severity Issues

#### H1. Stage Ordering Creates Rework
Stage 2 (Babel) modifies WG interface setup to add interfaces for Babel. Stage 3 (multi-link plugin) redesigns the interface abstraction. Stage 2's work gets partially rewritten in Stage 3.

**Mitigation**: Merge Stages 2 and 3. Design the multi-link abstraction first (even if only one link is active initially), then add Babel on top.

#### H2. Route Manager "Disable" Will Break Subnet Routing
The plan says "disable NetBird's own route installation for mesh peers." The route manager (`client/internal/routemanager/systemops/systemops_linux.go`) uses custom routing table `NetbirdVPNTableID = 0x1BD0` with ip rules at priorities 105/110, reference-counted route lifecycle, and tight coupling with ACL firewall rules. Disabling it wholesale breaks subnet route advertisement — a feature the plan explicitly wants to keep.

**Mitigation**: Create a routing strategy interface with two implementations: `NetBirdRouting` (current) and `BabelRouting` (delegates to babeld). Route manager selects strategy per route type.

#### H3. Multicast Beacon Crypto Uses Wrong Key Type
The plan signs multicast beacons with "Ed25519 using WireGuard private key." WireGuard keys are Curve25519 (X25519), not Ed25519. Converting between them requires a birational mapping with subtle pitfalls (sign bit ambiguity, cofactor handling).

**Mitigation**: Use XEd25519 signing (Signal Protocol spec) for proper Curve25519-to-Ed25519 conversion, or generate a separate Ed25519 signing key via HKDF from the WireGuard key.

#### H4. Static Roster Expiry Breaks Disconnected Operation
The roster has `expires_at` but no discussion of: what happens when it expires with no management server reachable (the primary tactical scenario), clock drift with no NTP, or whether expired roster means "deny all" vs. "use last known good."

**Mitigation**: Add configurable grace period after expiry. Add monotonic-time-based expiry option. Implement "last known good" fallback mode.

#### H5. babeld Sidecar Has Deployment Gaps
- babeld is a C program requiring separate compilation/packaging — no cross-compilation plan.
- babeld's text-based local socket interface is fragile for programmatic control.
- With N peers x M links, babeld manages N*M tunnel interfaces generating periodic updates — no scale analysis.
- No fallback for non-Linux platforms.

**Mitigation**: Define packaging/distribution for babeld. Consider a Go-native Babel implementation for tighter integration. Benchmark at target scale. Define non-Linux fallback (static routing from management server).

---

### Medium-Severity Issues

#### M1. Go Version Mismatch — Plan Is Stale
Plan says "Go 1.24"; actual codebase uses Go 1.25.5 (`go.mod` line 3). The plan's FIPS approach (`GODEBUG=fips140=on`) was a Go 1.24 feature — Go 1.25 may have different FIPS integration. Other code assumptions may also be stale.

#### M2. Existing Relay QUIC Usage Not Acknowledged
NetBird already uses `quic-go v0.55.0` for relay transport (`relay/server/listener/quic/`). Adding a second QUIC layer at the TUN level creates port conflicts and confusing failure modes.

#### M3. Testing Infrastructure Insufficient
3 Linux VMs cannot validate: RF link impairment (needs `tc netem`), scale (need 10+ node topology), disconnected operation scenarios, or FIPS compliance (requires CMVP validation, not just algorithm usage).

#### M4. ConnMgr Assumes Single Path per Peer
Peer store keys on pubKey alone. Multi-link requires per-link-per-peer connection state.

#### M5. Rosenpass Interaction Unaddressed
Codebase includes Rosenpass (post-quantum crypto, `cunicu.li/go-rosenpass v0.4.0`). Rosenpass uses non-FIPS algorithms (Classic McEliece). Plan doesn't mention it. Must decide: keep, remove, or adapt.

#### M6. No Fork Versioning Strategy
No plan for tracking upstream NetBird changes, managing merge conflicts, or maintaining the fork long-term. NetBird is actively developed — fork will rapidly diverge.

---

## Recommended Revised Stage Ordering

Based on the weakness analysis, the stages should be reordered to front-load the hardest risks:

| Stage | Name | Duration | Rationale |
|-------|------|----------|-----------|
| 0 | Fork Baseline + FIPS Envelope | 2w | Pin fork, replace NaCl with FIPS crypto envelope, update build system |
| 1 | Protocol Extensions | 2w | Extend management/signal protos for multi-link, design LinkConfig |
| 2 | LinkManager Abstraction | 4w | Introduce LinkManager between Engine and WGIface, refactor Engine |
| 3 | Babel Integration (single-link) | 2w | Add babeld sidecar over the new LinkManager abstraction |
| 4 | Multi-Link Transport + Discovery | 4w | WAN + Silvus transports, multicast/roster discovery plugins |
| 5 | LinkMonitor + PathSelector | 2w | Health monitoring, automatic failover, Babel metric feeds |
| 6 | FIPS Data Plane | 3w | Replace WG crypto with FIPS AEAD (not QUIC wrapper) |
| 7 | Offline Island + Caching | 2w | Peer cache, signed roster, ACL cache, disconnected operation |
| 8 | QoS + ECMP | 2w | Silvus API metrics, ECMP, advanced cost functions |
| **Total** | | **~23w** | |

Key changes from original:
1. FIPS moved to Stage 0 (protocol envelope) and Stage 6 (data plane) — risk front-loaded.
2. Protocol extensions added as Stage 1 — unblocks multi-link design.
3. LinkManager abstraction gets dedicated 4-week stage — reflects actual refactoring scope.
4. QUIC-over-WireGuard eliminated — replaced with WG crypto replacement approach.
5. Total estimate increased from 17 to 23 weeks — reflects realistic effort.

---

## Critical Files to Modify

| File | Change |
|------|--------|
| `encryption/encryption.go` | Replace NaCl box with FIPS crypto envelope |
| `shared/management/proto/management.proto` | Add LinkConfig, extend RemotePeerConfig |
| `shared/signal/proto/signalexchange.proto` | Add link identifier to ICE messages |
| `client/internal/engine.go` | Replace single `wgInterface` with LinkManager |
| `client/internal/peerstore/store.go` | Support per-link-per-peer connections |
| `client/internal/peer/conn.go` | Multi-link connection model |
| `client/internal/peer/worker_ice.go` | Per-link ICE negotiation |
| `client/internal/routemanager/` | Routing strategy interface (NetBird vs Babel) |
| `client/iface/iface.go` | No structural changes needed — instantiated multiple times |
| `client/internal/babel/` | New package: BabelManager sidecar lifecycle |
| `client/internal/link/` | New package: LinkTransport, Discovery, LinkMonitor, PathSelector |

---

## Verification Plan

1. **Unit tests**: Each new package (`babel/`, `link/`, crypto envelope) gets comprehensive unit tests.
2. **Integration tests**: 10-node topology using Linux network namespaces with `tc netem` for link impairment.
3. **FIPS verification**: `go tool nm <binary> | grep fips` confirms FIPS module linked. TLS handshake capture confirms FIPS cipher suites.
4. **Multi-link failover**: Sever primary link mid-flow, measure failover time (target <500ms).
5. **Offline convergence**: Disconnect management server, induce topology change, verify Babel reconverges.
6. **Scale test**: 50-node containerized mesh, measure routing convergence time and protocol overhead.
7. **Roster bootstrap**: Two nodes with no prior management contact form mesh from signed roster only.
