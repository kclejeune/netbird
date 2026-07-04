//go:build !js

package internal

import (
	"github.com/netbirdio/netbird/client/iface/udpmux"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// createICEConfig creates ICE configuration for the primary interface.
func (e *Engine) createICEConfig() icemaker.Config {
	return e.createICEConfigForMux(e.udpMux)
}

// createICEConfigForMux creates ICE configuration bound to a specific interface's
// UDP mux, so candidate gathering happens on the same interface a peer is
// programmed on. A nil mux yields a config without mux (host-only), used as a
// safe fallback.
func (e *Engine) createICEConfigForMux(mux *udpmux.UniversalUDPMuxDefault) icemaker.Config {
	cfg := icemaker.Config{
		StunTurn:             &e.stunTurn,
		InterfaceBlackList:   e.config.IFaceBlackList,
		DisableIPv6Discovery: e.config.DisableIPv6Discovery,
		NATExternalIPs:       e.parseNATExternalIPMappings(),
	}
	if mux != nil {
		cfg.UDPMux = mux.SingleSocketUDPMux
		cfg.UDPMuxSrflx = mux
	}
	return cfg
}
