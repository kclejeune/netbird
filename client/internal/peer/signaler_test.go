package peer

import (
	"context"
	"testing"

	"github.com/pion/ice/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// fakeSignalClient captures Send() calls so we can assert what the Signaler
// puts on the wire.
type fakeSignalClient struct {
	sent []*sProto.Message
}

func (f *fakeSignalClient) Close() error             { return nil }
func (f *fakeSignalClient) StreamConnected() bool    { return true }
func (f *fakeSignalClient) GetStatus() signal.Status { return signal.StreamConnected }
func (f *fakeSignalClient) Receive(context.Context, func(*sProto.Message) error) error {
	return nil
}
func (f *fakeSignalClient) Ready() bool                             { return true }
func (f *fakeSignalClient) IsHealthy() bool                         { return true }
func (f *fakeSignalClient) WaitStreamConnected()                    {}
func (f *fakeSignalClient) SendToStream(*sProto.EncryptedMessage) error { return nil }
func (f *fakeSignalClient) Send(m *sProto.Message) error            { f.sent = append(f.sent, m); return nil }
func (f *fakeSignalClient) SetOnReconnectedListener(func())         {}

func newTestSignaler(t *testing.T) (*Signaler, *fakeSignalClient) {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fc := &fakeSignalClient{}
	return NewSignaler(fc, key), fc
}

// TestSignaler_StampsLinkID verifies OFFER, ANSWER, and CANDIDATE messages all
// carry Body.linkId when the connection is bound to a non-default link.
func TestSignaler_StampsLinkID(t *testing.T) {
	s, fc := newTestSignaler(t)

	sid, err := NewICESessionID()
	if err != nil {
		t.Fatalf("NewICESessionID: %v", err)
	}
	off := OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufrag", Pwd: "pwd"},
		WgListenPort:   51820,
		SessionID:      &sid,
		LinkID:         "mesh0",
	}

	if err := s.SignalOffer(off, "remote-pub"); err != nil {
		t.Fatalf("SignalOffer: %v", err)
	}
	if err := s.SignalAnswer(off, "remote-pub"); err != nil {
		t.Fatalf("SignalAnswer: %v", err)
	}

	cand, err := ice.UnmarshalCandidate("candidate:1 1 udp 2130706431 192.168.1.1 51820 typ host")
	if err != nil {
		t.Fatalf("UnmarshalCandidate: %v", err)
	}
	if err := s.SignalICECandidate(cand, "remote-pub", "mesh0"); err != nil {
		t.Fatalf("SignalICECandidate: %v", err)
	}

	if len(fc.sent) != 3 {
		t.Fatalf("expected 3 sent messages, got %d", len(fc.sent))
	}
	for i, m := range fc.sent {
		if got := m.GetBody().GetLinkId(); got != "mesh0" {
			t.Fatalf("message %d (type %v): expected linkId=mesh0, got %q", i, m.GetBody().GetType(), got)
		}
	}
}

// TestSignaler_DefaultLinkEmptyID verifies the default/legacy link stamps an
// empty linkId, preserving wire compatibility with peers that ignore the field.
func TestSignaler_DefaultLinkEmptyID(t *testing.T) {
	s, fc := newTestSignaler(t)

	sid, err := NewICESessionID()
	if err != nil {
		t.Fatalf("NewICESessionID: %v", err)
	}
	off := OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "u", Pwd: "p"},
		SessionID:      &sid,
		// LinkID intentionally empty (default link).
	}
	if err := s.SignalOffer(off, "remote-pub"); err != nil {
		t.Fatalf("SignalOffer: %v", err)
	}

	cand, err := ice.UnmarshalCandidate("candidate:1 1 udp 2130706431 10.0.0.1 51820 typ host")
	if err != nil {
		t.Fatalf("UnmarshalCandidate: %v", err)
	}
	if err := s.SignalICECandidate(cand, "remote-pub", ""); err != nil {
		t.Fatalf("SignalICECandidate: %v", err)
	}

	for i, m := range fc.sent {
		if got := m.GetBody().GetLinkId(); got != "" {
			t.Fatalf("message %d: expected empty linkId for default link, got %q", i, got)
		}
	}
}
