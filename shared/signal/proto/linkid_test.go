package proto

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestBody_LinkId_RoundTrip(t *testing.T) {
	body := &Body{
		Type:    Body_OFFER,
		Payload: "test-offer",
		LinkId:  "silvus0",
	}

	data, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal Body: %v", err)
	}

	decoded := &Body{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal Body: %v", err)
	}

	if decoded.LinkId != "silvus0" {
		t.Fatalf("expected linkId 'silvus0', got %q", decoded.LinkId)
	}
	if decoded.Payload != "test-offer" {
		t.Fatalf("expected payload 'test-offer', got %q", decoded.Payload)
	}
}

func TestBody_LinkId_EmptyIsLegacy(t *testing.T) {
	// Legacy messages have no linkId — should unmarshal as empty string.
	body := &Body{
		Type:    Body_CANDIDATE,
		Payload: "legacy-candidate",
	}

	data, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &Body{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.GetLinkId() != "" {
		t.Fatalf("legacy message should have empty linkId, got %q", decoded.GetLinkId())
	}
}
