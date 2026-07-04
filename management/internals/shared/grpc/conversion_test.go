package grpc

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestAppendRemotePeerConfig_Links(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			Key: "pubA",
			IP:  net.ParseIP("100.64.0.2"),
			MeshLinks: []nbpeer.MeshLink{{
				LinkID:           "mesh0",
				TransportType:    "wireguard",
				Endpoint:         "10.0.0.2:51820",
				MTU:              1280,
				Priority:         10,
				Cost:             50,
				WgIfaceName:      "wt-mesh0",
				MulticastEnabled: true,
			}},
		},
		{Key: "pubB", IP: net.ParseIP("100.64.0.3")}, // no links
	}

	out := appendRemotePeerConfig(nil, peers, "example.com", nil)
	if len(out) != 2 {
		t.Fatalf("expected 2 remote peer configs, got %d", len(out))
	}

	// Base fields still set as before.
	if out[0].GetWgPubKey() != "pubA" || out[0].GetAllowedIps()[0] != "100.64.0.2/32" {
		t.Fatalf("base fields wrong: %+v", out[0])
	}

	// Peer A links populated and mapped field-for-field.
	la := out[0].GetLinks()
	if len(la) != 1 {
		t.Fatalf("peerA expected 1 link, got %d", len(la))
	}
	l := la[0]
	if l.GetLinkId() != "mesh0" || l.GetTransportType() != "wireguard" ||
		l.GetEndpoint() != "10.0.0.2:51820" || l.GetMtu() != 1280 ||
		l.GetPriority() != 10 || l.GetCost() != 50 ||
		l.GetWgIfaceName() != "wt-mesh0" || !l.GetMulticastEnabled() {
		t.Fatalf("peerA link fields wrong: %+v", l)
	}

	// Peer B has no links -> nil, preserving pre-multi-link wire format.
	if len(out[1].GetLinks()) != 0 {
		t.Fatalf("peerB should have no links, got %d", len(out[1].GetLinks()))
	}
}

func TestAppendRemotePeerConfig_ConfigLinks(t *testing.T) {
	// Config assigns links to pubB; pubA has an in-memory override; pubC neither.
	configLinks := meshLinksByPeer([]nbconfig.MeshLinkAssignment{
		{
			PeerKey: "pubB",
			Links: []nbconfig.MeshLink{{
				LinkID:        "silvus0",
				TransportType: "wireguard",
				Endpoint:      "10.9.9.9:51820",
				Priority:      20,
				Cost:          70,
			}},
		},
	})

	peers := []*nbpeer.Peer{
		{
			Key: "pubA", IP: net.ParseIP("100.64.0.2"),
			MeshLinks: []nbpeer.MeshLink{{LinkID: "mesh0", TransportType: "wireguard", Endpoint: "10.0.0.2:51820"}},
		},
		{Key: "pubB", IP: net.ParseIP("100.64.0.3")},
		{Key: "pubC", IP: net.ParseIP("100.64.0.4")},
	}

	out := appendRemotePeerConfig(nil, peers, "example.com", configLinks)
	if len(out) != 3 {
		t.Fatalf("expected 3, got %d", len(out))
	}

	// pubA: in-memory override wins over config (config has none for it anyway).
	if la := out[0].GetLinks(); len(la) != 1 || la[0].GetLinkId() != "mesh0" {
		t.Fatalf("pubA should use in-memory link mesh0, got %+v", la)
	}
	// pubB: sourced from config.
	lb := out[1].GetLinks()
	if len(lb) != 1 || lb[0].GetLinkId() != "silvus0" || lb[0].GetEndpoint() != "10.9.9.9:51820" ||
		lb[0].GetPriority() != 20 || lb[0].GetCost() != 70 {
		t.Fatalf("pubB should use config link silvus0, got %+v", lb)
	}
	// pubC: no links from either source.
	if len(out[2].GetLinks()) != 0 {
		t.Fatalf("pubC should have no links, got %d", len(out[2].GetLinks()))
	}
}

func TestMeshLinksByPeer_Empty(t *testing.T) {
	if m := meshLinksByPeer(nil); m != nil {
		t.Fatalf("expected nil map for no assignments, got %v", m)
	}
}

func TestToProtocolDNSConfigWithCache(t *testing.T) {
	var cache cache.DNSConfigCache

	// Create two different configs
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.com",
				Records: []nbdns.SimpleRecord{
					{Name: "www", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.1"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group1",
				Name: "Group 1",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
				},
			},
		},
	}

	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.org",
				Records: []nbdns.SimpleRecord{
					{Name: "mail", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.2"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group2",
				Name: "Group 2",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.4.4"), Port: 53},
				},
			},
		},
	}

	// First run with config1
	result1 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Second run with config2
	result2 := toProtocolDNSConfig(config2, &cache, int64(network_map.DnsForwarderPort))

	// Third run with config1 again
	result3 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Verify that result1 and result3 are identical
	if !reflect.DeepEqual(result1, result3) {
		t.Errorf("Results are not identical when run with the same input. Expected %v, got %v", result1, result3)
	}

	// Verify that result2 is different from result1 and result3
	if reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result2, result3) {
		t.Errorf("Results should be different for different inputs")
	}

	if _, exists := cache.GetNameServerGroup("group1"); !exists {
		t.Errorf("Cache should contain name server group 'group1'")
	}

	if _, exists := cache.GetNameServerGroup("group2"); !exists {
		t.Errorf("Cache should contain name server group 'group2'")
	}
}

func BenchmarkToProtocolDNSConfig(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		testData := generateTestData(size)

		b.Run(fmt.Sprintf("WithCache-Size%d", size), func(b *testing.B) {
			cache := &cache.DNSConfigCache{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})

		b.Run(fmt.Sprintf("WithoutCache-Size%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := &cache.DNSConfigCache{}
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})
	}
}

func generateTestData(size int) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      make([]nbdns.CustomZone, size),
		NameServerGroups: make([]*nbdns.NameServerGroup, size),
	}

	for i := 0; i < size; i++ {
		config.CustomZones[i] = nbdns.CustomZone{
			Domain: fmt.Sprintf("domain%d.com", i),
			Records: []nbdns.SimpleRecord{
				{
					Name:  fmt.Sprintf("record%d", i),
					Type:  1,
					Class: "IN",
					TTL:   3600,
					RData: "192.168.1.1",
				},
			},
		}

		config.NameServerGroups[i] = &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("group%d", i),
			Primary:              i == 0,
			Domains:              []string{fmt.Sprintf("domain%d.com", i)},
			SearchDomainsEnabled: true,
			NameServers: []nbdns.NameServer{
				{
					IP:     netip.MustParseAddr("8.8.8.8"),
					Port:   53,
					NSType: 1,
				},
			},
		}
	}

	return config
}

func TestBuildJWTConfig_Audiences(t *testing.T) {
	tests := []struct {
		name              string
		authAudience      string
		cliAuthAudience   string
		expectedAudiences []string
		expectedAudience  string
	}{
		{
			name:              "only_auth_audience",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "",
			expectedAudiences: []string{"dashboard-aud"},
			expectedAudience:  "dashboard-aud",
		},
		{
			name:              "both_audiences_different",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "cli-aud",
			expectedAudiences: []string{"dashboard-aud", "cli-aud"},
			expectedAudience:  "cli-aud",
		},
		{
			name:              "both_audiences_same",
			authAudience:      "same-aud",
			cliAuthAudience:   "same-aud",
			expectedAudiences: []string{"same-aud"},
			expectedAudience:  "same-aud",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &nbconfig.HttpServerConfig{
				AuthIssuer:      "https://issuer.example.com",
				AuthAudience:    tc.authAudience,
				CLIAuthAudience: tc.cliAuthAudience,
			}

			result := buildJWTConfig(config, nil)

			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedAudiences, result.Audiences, "audiences should match expected")
			//nolint:staticcheck // SA1019: Testing backwards compatibility - Audience field must still be populated
			assert.Equal(t, tc.expectedAudience, result.Audience, "audience should match expected")
		})
	}
}
