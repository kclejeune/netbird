package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/auth"
)

func meshLinksRequest(t *testing.T, method, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/api/peers/p1/mesh-links", nil)
	} else {
		r = httptest.NewRequest(method, "/api/peers/p1/mesh-links", bytes.NewBufferString(body))
	}
	r = mux.SetURLVars(r, map[string]string{"peerId": "p1"})
	return nbcontext.SetUserAuthInRequest(r, auth.UserAuth{UserId: adminUser, AccountId: "test_id", Domain: "hotmail.com"})
}

func TestGetPeerMeshLinks(t *testing.T) {
	h := &Handler{accountManager: &mock_server.MockAccountManager{
		GetPeerFunc: func(_ context.Context, _, peerID, _ string) (*nbpeer.Peer, error) {
			return &nbpeer.Peer{ID: peerID, MeshLinks: []nbpeer.MeshLink{
				{LinkID: "mesh0", TransportType: "wireguard", Endpoint: "10.0.0.2:51820", Priority: 10, Cost: 50},
			}}, nil
		},
	}}

	rr := httptest.NewRecorder()
	h.GetPeerMeshLinks(rr, meshLinksRequest(t, http.MethodGet, ""))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, body %s", rr.Code, rr.Body.String())
	}
	var got []MeshLinkAPI
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].LinkId != "mesh0" || got[0].Endpoint != "10.0.0.2:51820" || got[0].Cost != 50 {
		t.Fatalf("unexpected links: %+v", got)
	}
}

func TestSetPeerMeshLinks(t *testing.T) {
	var saved []nbpeer.MeshLink
	h := &Handler{accountManager: &mock_server.MockAccountManager{
		SetPeerMeshLinksFunc: func(_ context.Context, _, peerID, _ string, links []nbpeer.MeshLink) (*nbpeer.Peer, error) {
			saved = links
			return &nbpeer.Peer{ID: peerID, MeshLinks: links}, nil
		},
	}}

	body := `[{"linkId":"silvus0","transportType":"wireguard","endpoint":"10.9.9.9:51820","priority":20,"cost":70}]`
	rr := httptest.NewRecorder()
	h.SetPeerMeshLinks(rr, meshLinksRequest(t, http.MethodPut, body))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, body %s", rr.Code, rr.Body.String())
	}
	if len(saved) != 1 || saved[0].LinkID != "silvus0" || saved[0].MTU != 0 || saved[0].Priority != 20 || saved[0].Cost != 70 {
		t.Fatalf("SetPeerMeshLinks got wrong links: %+v", saved)
	}
	var got []MeshLinkAPI
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got) != 1 || got[0].LinkId != "silvus0" {
		t.Fatalf("response wrong: %+v", got)
	}
}

func TestSetPeerMeshLinks_RejectsMissingLinkId(t *testing.T) {
	h := &Handler{accountManager: &mock_server.MockAccountManager{
		SetPeerMeshLinksFunc: func(_ context.Context, _, _, _ string, _ []nbpeer.MeshLink) (*nbpeer.Peer, error) {
			t.Fatal("manager should not be called on invalid input")
			return nil, nil
		},
	}}

	rr := httptest.NewRecorder()
	h.SetPeerMeshLinks(rr, meshLinksRequest(t, http.MethodPut, `[{"endpoint":"x:1"}]`))

	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 for missing linkId, got %d", rr.Code)
	}
}
