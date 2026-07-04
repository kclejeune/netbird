package internal

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/link"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// TestSelectICEConfig verifies ICE config selection routes a peer's candidate
// gathering to the interface it is programmed on: mesh links use their own
// interface-bound config, and the primary/default (or unknown) link uses the
// default config.
func TestSelectICEConfig(t *testing.T) {
	// Tag each config distinctly via InterfaceBlackList[0] to identify it.
	def := icemaker.Config{InterfaceBlackList: []string{"default"}}
	mesh := icemaker.Config{InterfaceBlackList: []string{"mesh"}}
	perLink := map[string]icemaker.Config{"mesh0": mesh}

	tag := func(c icemaker.Config) string {
		if len(c.InterfaceBlackList) == 0 {
			return ""
		}
		return c.InterfaceBlackList[0]
	}

	cases := []struct {
		name   string
		linkID string
		perLnk map[string]icemaker.Config
		want   string
	}{
		{"primary link uses default", link.PrimaryLinkID, perLink, "default"},
		{"empty link uses default", "", perLink, "default"},
		{"mesh link uses its own config", "mesh0", perLink, "mesh"},
		{"unknown mesh link falls back to default", "meshX", perLink, "default"},
		{"nil per-link map uses default", "mesh0", nil, "default"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectICEConfig(tc.linkID, def, tc.perLnk)
			if tag(got) != tc.want {
				t.Fatalf("linkID=%q: expected %q config, got %q", tc.linkID, tc.want, tag(got))
			}
		})
	}
}
