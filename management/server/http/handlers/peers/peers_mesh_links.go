package peers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// MeshLinkAPI is the JSON representation of a peer transport link. It is defined
// locally (rather than in the generated api package) so the mesh-links admin
// endpoint can ship without an OpenAPI regeneration; the field names match the
// proto LinkConfig and the client-side mesh link types.
type MeshLinkAPI struct {
	LinkId           string `json:"linkId"`
	TransportType    string `json:"transportType,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	Mtu              uint32 `json:"mtu,omitempty"`
	Priority         uint32 `json:"priority,omitempty"`
	Cost             uint32 `json:"cost,omitempty"`
	WgIfaceName      string `json:"wgIfaceName,omitempty"`
	MulticastEnabled bool   `json:"multicastEnabled,omitempty"`
}

func toMeshLinkAPI(l nbpeer.MeshLink) MeshLinkAPI {
	return MeshLinkAPI{
		LinkId:           l.LinkID,
		TransportType:    l.TransportType,
		Endpoint:         l.Endpoint,
		Mtu:              l.MTU,
		Priority:         l.Priority,
		Cost:             l.Cost,
		WgIfaceName:      l.WgIfaceName,
		MulticastEnabled: l.MulticastEnabled,
	}
}

func fromMeshLinkAPI(l MeshLinkAPI) nbpeer.MeshLink {
	return nbpeer.MeshLink{
		LinkID:           l.LinkId,
		TransportType:    l.TransportType,
		Endpoint:         l.Endpoint,
		MTU:              l.Mtu,
		Priority:         l.Priority,
		Cost:             l.Cost,
		WgIfaceName:      l.WgIfaceName,
		MulticastEnabled: l.MulticastEnabled,
	}
}

func meshLinksResponse(links []nbpeer.MeshLink) []MeshLinkAPI {
	out := make([]MeshLinkAPI, 0, len(links))
	for _, l := range links {
		out = append(out, toMeshLinkAPI(l))
	}
	return out
}

// GetPeerMeshLinks returns the transport links assigned to a peer.
func (h *Handler) GetPeerMeshLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	peerID := mux.Vars(r)["peerId"]

	peer, err := h.accountManager.GetPeer(ctx, userAuth.AccountId, peerID, userAuth.UserId)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	util.WriteJSONObject(ctx, w, meshLinksResponse(peer.MeshLinks))
}

// SetPeerMeshLinks replaces the transport links assigned to a peer.
func (h *Handler) SetPeerMeshLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	peerID := mux.Vars(r)["peerId"]

	var req []MeshLinkAPI
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}
	for _, l := range req {
		if l.LinkId == "" {
			util.WriteError(ctx, status.Errorf(status.InvalidArgument, "each mesh link requires a linkId"), w)
			return
		}
	}

	links := make([]nbpeer.MeshLink, 0, len(req))
	for _, l := range req {
		links = append(links, fromMeshLinkAPI(l))
	}

	peer, err := h.accountManager.SetPeerMeshLinks(ctx, userAuth.AccountId, peerID, userAuth.UserId, links)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
	util.WriteJSONObject(ctx, w, meshLinksResponse(peer.MeshLinks))
}
