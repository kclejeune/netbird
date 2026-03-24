package proto

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestLinkConfig_MarshalRoundTrip(t *testing.T) {
	lc := &LinkConfig{
		LinkId:           "silvus0",
		TransportType:    "wireguard",
		Endpoint:         "239.1.1.1:5353",
		Mtu:              1280,
		Priority:         5,
		Cost:             100,
		WgIfaceName:      "wg-silvus0",
		MulticastEnabled: true,
	}

	data, err := proto.Marshal(lc)
	if err != nil {
		t.Fatalf("Marshal LinkConfig: %v", err)
	}

	decoded := &LinkConfig{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal LinkConfig: %v", err)
	}

	if decoded.LinkId != lc.LinkId {
		t.Fatalf("LinkId: expected %q, got %q", lc.LinkId, decoded.LinkId)
	}
	if decoded.TransportType != lc.TransportType {
		t.Fatalf("TransportType: expected %q, got %q", lc.TransportType, decoded.TransportType)
	}
	if decoded.Endpoint != lc.Endpoint {
		t.Fatalf("Endpoint: expected %q, got %q", lc.Endpoint, decoded.Endpoint)
	}
	if decoded.Mtu != lc.Mtu {
		t.Fatalf("Mtu: expected %d, got %d", lc.Mtu, decoded.Mtu)
	}
	if decoded.Priority != lc.Priority {
		t.Fatalf("Priority: expected %d, got %d", lc.Priority, decoded.Priority)
	}
	if decoded.Cost != lc.Cost {
		t.Fatalf("Cost: expected %d, got %d", lc.Cost, decoded.Cost)
	}
	if decoded.WgIfaceName != lc.WgIfaceName {
		t.Fatalf("WgIfaceName: expected %q, got %q", lc.WgIfaceName, decoded.WgIfaceName)
	}
	if decoded.MulticastEnabled != lc.MulticastEnabled {
		t.Fatalf("MulticastEnabled: expected %v, got %v", lc.MulticastEnabled, decoded.MulticastEnabled)
	}
}

func TestLinkStatusUpdate_MarshalRoundTrip(t *testing.T) {
	lsu := &LinkStatusUpdate{
		LinkId:        "wan0",
		Up:            true,
		LatencyMs:     42,
		LossPercent:   3,
		BandwidthKbps: 50000,
	}

	data, err := proto.Marshal(lsu)
	if err != nil {
		t.Fatalf("Marshal LinkStatusUpdate: %v", err)
	}

	decoded := &LinkStatusUpdate{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal LinkStatusUpdate: %v", err)
	}

	if decoded.LinkId != lsu.LinkId {
		t.Fatalf("LinkId mismatch")
	}
	if decoded.Up != lsu.Up {
		t.Fatalf("Up mismatch")
	}
	if decoded.LatencyMs != lsu.LatencyMs {
		t.Fatalf("LatencyMs mismatch")
	}
	if decoded.LossPercent != lsu.LossPercent {
		t.Fatalf("LossPercent mismatch")
	}
	if decoded.BandwidthKbps != lsu.BandwidthKbps {
		t.Fatalf("BandwidthKbps mismatch")
	}
}

func TestRemotePeerConfig_WithLinks(t *testing.T) {
	rpc := &RemotePeerConfig{
		WgPubKey:   "test-pub-key",
		AllowedIps: []string{"10.0.0.1/32"},
		Fqdn:       "peer1.netbird.local",
		Links: []*LinkConfig{
			{
				LinkId:        "wan0",
				TransportType: "wireguard",
				Priority:      0,
			},
			{
				LinkId:        "silvus0",
				TransportType: "wireguard",
				Priority:      10,
				Cost:          50,
			},
		},
	}

	data, err := proto.Marshal(rpc)
	if err != nil {
		t.Fatalf("Marshal RemotePeerConfig: %v", err)
	}

	decoded := &RemotePeerConfig{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal RemotePeerConfig: %v", err)
	}

	if len(decoded.Links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(decoded.Links))
	}
	if decoded.Links[0].LinkId != "wan0" {
		t.Fatalf("first link should be wan0, got %s", decoded.Links[0].LinkId)
	}
	if decoded.Links[1].LinkId != "silvus0" {
		t.Fatalf("second link should be silvus0, got %s", decoded.Links[1].LinkId)
	}
	if decoded.Links[1].Cost != 50 {
		t.Fatalf("silvus0 cost should be 50, got %d", decoded.Links[1].Cost)
	}
}

func TestRemotePeerConfig_NoLinks_BackwardCompat(t *testing.T) {
	// Legacy peers send no links field — should unmarshal cleanly with nil/empty links.
	rpc := &RemotePeerConfig{
		WgPubKey:   "legacy-peer",
		AllowedIps: []string{"10.0.0.2/32"},
	}

	data, err := proto.Marshal(rpc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &RemotePeerConfig{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.GetLinks()) != 0 {
		t.Fatalf("legacy peer should have 0 links, got %d", len(decoded.GetLinks()))
	}
}
