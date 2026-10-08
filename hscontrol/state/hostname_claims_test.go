package state

import (
	"fmt"
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

func TestOrderClaimRecordsForViewer(t *testing.T) {
	const name = "cca.gw.example.com"

	recordsFor := func(nodes ...types.NodeID) []claimRecord {
		records := make([]claimRecord, 0, 2*len(nodes))

		for _, id := range nodes {
			v4 := fmt.Sprintf("100.64.0.%d", id)
			v6 := fmt.Sprintf("fd7a:115c:a1e0::%d", id)
			records = append(records,
				claimRecord{nodeID: id, record: tailcfg.DNSRecord{Name: name, Type: "A", Value: v4}},
				claimRecord{nodeID: id, record: tailcfg.DNSRecord{Name: name, Type: "AAAA", Value: v6}},
			)
		}

		return records
	}

	// chosen returns the node whose addresses a client answers with: the
	// first A and the first AAAA record, which must be the same node.
	chosen := func(t *testing.T, viewer types.NodeID, nodes ...types.NodeID) types.NodeID {
		t.Helper()

		records := recordsFor(nodes...)
		orderClaimRecordsForViewer(records, viewer)

		firstOf := func(typ string) types.NodeID {
			for _, r := range records {
				if r.record.Type == typ {
					return r.nodeID
				}
			}

			return 0
		}

		a, aaaa := firstOf("A"), firstOf("AAAA")
		assert.Equal(t, a, aaaa, "viewer %d must get A and AAAA of one node", viewer)

		return a
	}

	const viewers = 1000

	counts := map[types.NodeID]int{}
	before := map[types.NodeID]types.NodeID{}

	for v := types.NodeID(100); v < 100+viewers; v++ {
		n := chosen(t, v, 1, 2, 3)
		before[v] = n
		counts[n]++
	}

	for _, id := range []types.NodeID{1, 2, 3} {
		// Each of three nodes gets about a third; allow a wide bound.
		assert.InDelta(t, viewers/3, counts[id], viewers/10, "node %d share", id)
	}

	// Node 2 leaves: only the viewers that chose it move.
	for v := types.NodeID(100); v < 100+viewers; v++ {
		after := chosen(t, v, 1, 3)
		if before[v] != 2 {
			assert.Equal(t, before[v], after, "viewer %d moved although its node stayed", v)
		}
	}
}
