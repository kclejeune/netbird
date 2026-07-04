# TacMesh — MANET / multi-link features

This fork adds tactical-mesh (MANET) capabilities to NetBird: multi-link
transport with health-aware path selection, Babel dynamic routing, a signed
roster with multicast discovery for disconnected operation, and FIPS-oriented
crypto. This document is the feature + configuration reference and an honest
status of what is code-complete versus what still needs live multi-node
verification. Design rationale and the original weakness analysis live in
`TACMESH_PLAN_REVIEW.md`.

## Client configuration (`profilemanager.Config`)

| Key | Meaning |
|---|---|
| `CipherType` | Management/signal cipher: `""`/`nacl` (default, upstream-compatible) or `aesgcm`. |
| `BabelEnabled` | Run the babeld routing sidecar for mesh links (Linux; babeld must be installed). |
| `MeshLinks` | Locally-configured secondary WireGuard interfaces + their static peers. |
| `RosterPath` | Path to a signed peer roster for offline-island operation. |
| `RosterTrustAnchor` | base64 Ed25519 public key of the roster authority. |
| `RosterGraceSeconds` | Grace period past roster expiry (0 = 24h default). |
| `RosterMulticastGroup` | e.g. `239.9.9.9:5353` — enables multicast beacon discovery. |
| `RosterAdvertiseEndpoint` | host:port this node announces in beacons (empty = receive-only). |

CLI flags exist for `--cipher-type` and `--enable-babel`; the rest are profile
config fields.

## Admin API (management server)

`GET`/`PUT /api/peers/{peerId}/mesh-links` — read/replace the transport links a
peer is reachable over (persisted; distributed to peers in the network map). A
static config source also exists (`nbconfig.Config.MeshLinks`). Documented in
`shared/management/http/api/openapi.yml`. The dashboard adds a **Mesh Links** tab
on the peer page.

## Path selection (QoS)

`link.Manager.SelectLink` orders candidate links by admin `Priority`, breaking
ties on observed health (latency + loss from the LinkMonitor) with a hysteresis
margin to avoid flapping. Babel neighbour RTT feeds the monitor, so Babel metrics
influence selection.

### ECMP

Equal-cost multipath load-*spreading* of a single flow is not done at the
WireGuard-peer layer: WireGuard maps a destination prefix to exactly one
peer-tunnel, so there is no per-packet split there. ECMP is instead a
**kernel/Babel-layer** concern — babeld can install multipath (multiple
next-hop) routes for a mesh prefix reachable via several neighbours, into its
dedicated export table. The route-strategy rule (below) already steers mesh-
prefix traffic to that table, so enabling ECMP is a babeld configuration matter,
not additional client per-packet balancing. Per-flow selection across links is
handled by the QoS `SelectLink` above.

## Babel routing

babeld runs as a supervised sidecar, config-file-driven, exporting routes into a
dedicated kernel table (default 100). A policy-routing rule steers the mesh
prefix (`100.64.0.0/10`) to that table at priority 108 (between NetBird's 105/110
rules); a table miss falls through to NetBird's own installer, so normal peer
traffic is unaffected. `DisableKernelRules` opts out of the steering rule.

## Offline island (signed roster)

A roster is a list of allowed peers signed by a mission authority (Ed25519),
verified against `RosterTrustAnchor`. Freshness uses expiry + grace + a
monotonic-anchored clock (a wrong wall clock can't force accept/reject), with a
last-known-good disk fallback for degraded operation. Multicast **beacons**
announce each node's endpoint; beacons are authenticated with a per-node Ed25519
key **derived from the WireGuard key via HKDF** and bound into the roster — this
avoids the error-prone Curve25519→Ed25519 (XEd25519) conversion the original plan
proposed. Discovered peers are programmed automatically.

## Crypto / FIPS status

- `encryption` Cipher envelope supports `nacl` (default) and `aesgcm`
  (X25519 + AES-256-GCM). AES-GCM/SHA-256 are FIPS-approved but **X25519 key
  agreement is not** (SP 800-56A), so `aesgcm` is not end-to-end FIPS.
- `encryption.SealP256`/`OpenP256` is a **genuinely FIPS-approved** envelope
  (P-256 ECDH + HKDF-SHA256 + AES-256-GCM) using dedicated P-256 keys. It is the
  building block for FIPS control-plane crypto; adopting it as the live envelope
  requires a P-256 node-identity/distribution layer (the Cipher interface is
  keyed by WireGuard Curve25519 keys today). This is the remaining FIPS wiring.

## Outstanding (needs a live multi-node Linux setup)

- Real babeld two-node forwarding + the netlink steering rule end to end.
- ICE-over-mesh handshake completion (per-interface ICE plumbing is in place).
- Beacon discovery on a real multicast segment.
- P-256 node-identity layer to make the FIPS envelope the live control-plane cipher.
