# Patches

## dashboard-mesh-links.patch

Adds a **Mesh Links** tab to the peer detail page in the NetBird dashboard
(`kclejeune/dashboard` / `netbirdio/dashboard`), backed by the
`GET`/`PUT /api/peers/{peerId}/mesh-links` admin API added on the management
server in this branch. It could not be pushed from the automated session (the
session's git proxy only permits the `netbird` repo), so it is checked in here
to apply in the dashboard checkout.

Apply from the root of a dashboard clone:

```sh
git checkout -b mesh-links
git am < /path/to/patches/dashboard-mesh-links.patch
npm install   # if not already
npx tsc --noEmit   # optional: the new files typecheck clean
```

Files added/changed by the patch:
- `src/interfaces/MeshLink.ts` (new)
- `src/modules/peer/PeerMeshLinksSection.tsx` (new)
- `src/app/(dashboard)/peer/page.tsx` (adds the tab)
