//go:build js

package internal

import (
	"github.com/netbirdio/netbird/client/iface/udpmux"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// createICEConfig creates ICE configuration for WASM environment.
func (e *Engine) createICEConfig() icemaker.Config {
	return e.createICEConfigForMux(nil)
}

// createICEConfigForMux mirrors the non-WASM signature; WASM has no UDP mux, so
// the mux argument is ignored.
func (e *Engine) createICEConfigForMux(_ *udpmux.UniversalUDPMuxDefault) icemaker.Config {
	return icemaker.Config{
		StunTurn:             &e.stunTurn,
		InterfaceBlackList:   e.config.IFaceBlackList,
		DisableIPv6Discovery: e.config.DisableIPv6Discovery,
		NATExternalIPs:       e.parseNATExternalIPMappings(),
	}
}
