package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestDeriveClaimRecords(t *testing.T) {
	addr := func(s string) *netip.Addr { return new(netip.MustParseAddr(s)) }

	node := func(id types.NodeID, online bool, v4, v6 string, services ...string) types.NodeView {
		n := &types.Node{
			ID:                 id,
			Tags:               []string{"tag:gateway"},
			IsOnline:           new(online),
			AdvertisedServices: services,
		}
		if v4 != "" {
			n.IPv4 = addr(v4)
		}

		if v6 != "" {
			n.IPv6 = addr(v6)
		}

		return n.View()
	}

	// claimAll lets every node claim <label>.gw.example.com, and
	// <label>.headscale.net to exercise the MagicDNS collision guard.
	claimAll := func(_ types.NodeView, services []string) []string {
		names := make([]string, 0, 2*len(services))

		for _, svc := range services {
			label := tailcfg.ServiceName(svc).WithoutPrefix()
			names = append(names, label+".gw.example.com", label+".headscale.net")
		}

		return names
	}

	nodes := views.SliceOf([]types.NodeView{
		node(3, true, "100.64.0.3", "fd7a:115c:a1e0::3", "svc:cca"),
		node(1, true, "100.64.0.1", "fd7a:115c:a1e0::1", "svc:cca"),
		node(2, false, "100.64.0.2", "", "svc:cca"),
		node(4, true, "100.64.0.4", "", "svc:web"),
		node(5, true, "100.64.0.5", ""),
	})

	got := deriveClaimRecords(nodes, claimAll, "headscale.net")

	want := []claimRecord{
		{nodeID: 1, record: tailcfg.DNSRecord{Name: "cca.gw.example.com", Type: "A", Value: "100.64.0.1"}},
		{nodeID: 3, record: tailcfg.DNSRecord{Name: "cca.gw.example.com", Type: "A", Value: "100.64.0.3"}},
		{nodeID: 1, record: tailcfg.DNSRecord{Name: "cca.gw.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::1"}},
		{nodeID: 3, record: tailcfg.DNSRecord{Name: "cca.gw.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::3"}},
		{nodeID: 4, record: tailcfg.DNSRecord{Name: "web.gw.example.com", Type: "A", Value: "100.64.0.4"}},
	}

	assert.Equal(t, want, got, "offline node 2, node 5 without services and names in the base domain must be absent")
}
