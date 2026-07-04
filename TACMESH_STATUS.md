# TacMesh — delivery status

Status log for the TacMesh (MANET / multi-link) work on branch
`claude/review-netbird-plan-h3ftb`. Design/analysis is in
`TACMESH_PLAN_REVIEW.md`; the feature + config reference is in `TACMESH.md`.

All items below are code-complete and pass `go test -race` for their packages;
generic **and** `js/wasm` client builds are clean. Items needing a live
multi-node Linux setup for end-to-end validation are called out under
"Remaining".

## Delivered (feature → commit)

| # | Feature | Commit |
|---|---|---|
| 0–1 | Stage 0-2: FIPS crypto envelope, proto extensions, LinkManager; tests; babel scaffolding; race fix | `2b46941`, `28bdcab` |
| — | Wire multi-link subsystem + begin multi-interface refactor | `d81caaf` |
| 1 | Mocked babeld runtime tests (socket protocol + process lifecycle) | `c6c2e32` |
| 2 | Per-link signal `linkId` plumbing through the peer-connection path | `2496f2c` |
| 3 | Consume Babel routes via a mockable policy-routing strategy | `bc479c5` |
| 4 | Distribute per-peer mesh links in the network map | `63cf904` |
| 5 | Config-file source for server-side mesh links | `09d864e` |
| 6 | Per-interface ICE config selection | `d3ea424` |
| 7 | Persisted peer mesh-links admin API (`GET/PUT /api/peers/{id}/mesh-links`) | `9604dc9` |
| 8 | Dashboard "Mesh Links" tab (typechecks clean) | see `patches/` |
| 9 | Signed roster for offline-island operation (H3/H4) | `8ebb367` |
| 10 | QoS-aware path selection (latency tiebreak + hysteresis) | `0c46fc7` |
| 11 | Multicast beacon transport for roster peer discovery | `6d73778` |
| 12 | FIPS-approved P-256 envelope, OpenAPI mesh-links spec, docs | `ff994b0` |
| — | Dashboard patch checked in for out-of-band apply | `3718e92` |

## Dashboard (`kclejeune/dashboard`)

The "Mesh Links" tab commit could not be pushed from the automated session
(the git proxy only permits the `netbird` repo). It is checked in as
`patches/dashboard-mesh-links.patch` with apply instructions in
`patches/README.md`. Apply it in a dashboard clone (`git am < …`) or push the
branch once the dashboard repo is added to a session.

## Remaining (needs a live multi-node Linux environment)

- Real babeld two-node forwarding + the netlink steering rule, end to end.
- ICE-over-mesh handshake completion (per-interface ICE plumbing is in place).
- Beacon discovery on a real multicast segment.
- A P-256 node-identity/distribution layer to make `SealP256`/`OpenP256` the
  live control-plane envelope (the FIPS wiring gap; the primitive is done).
- ECMP: enabled at the babeld/kernel-multipath layer via the export-table
  steering rule (see `TACMESH.md`); no additional client code required.
