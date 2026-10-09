package state

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const (
	benchServiceHosts = 3
	benchService      = tailcfg.ServiceName("svc:grafana")
)

// benchServiceState builds a State with n online nodes that all see each
// other (allow-all policy, the worst case for peer sets): three hosts of
// svc:grafana and n-3 clients.
func benchServiceState(b *testing.B, n int) *State {
	b.Helper()

	user := types.User{ID: 1, Name: "bench"}

	nodes := make(types.Nodes, 0, n)

	for i := range n {
		id := types.NodeID(i + 1) //nolint:gosec // small bench IDs
		v4 := netip.AddrFrom4([4]byte{100, 64, byte((i + 1) >> 8), byte(i + 1)})
		v6 := netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", i+1))

		node := &types.Node{
			ID:       id,
			Hostname: fmt.Sprintf("node-%d", i+1),
			IPv4:     &v4,
			IPv6:     &v6,
			IsOnline: new(true),
		}

		if i < benchServiceHosts {
			node.Tags = []string{"tag:grafana"}
			node.AdvertisedServices = []string{benchService.String()}
		} else {
			node.UserID = &user.ID
			node.User = &user
		}

		nodes = append(nodes, node)
	}

	pol := []byte(`{
		"tagOwners": {"tag:grafana": ["bench@"]},
		"autoApprovers": {"services": {"svc:grafana": ["tag:grafana"]}},
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]
	}`)

	pm, err := policy.NewPolicyManager(pol, []types.User{user}, nodes.ViewSlice())
	require.NoError(b, err)

	vips := serviceVIPMap{benchService: {
		netip.MustParseAddr("100.127.0.1"),
		netip.MustParseAddr("fd7a:115c:a1e0:ffff::1"),
	}}

	_, err = pm.SetServiceVIPs(vips)
	require.NoError(b, err)

	store := NewNodeStore(nodes, policyPeersFunc(pm), TestBatchSize, TestBatchTimeout)
	store.Start()
	b.Cleanup(store.Stop)

	s := &State{
		cfg:       &types.Config{},
		polMan:    pm,
		nodeStore: store,
	}
	s.services.vips.Store(&vips)
	s.refreshServiceHosts()

	return s
}

// BenchmarkServiceRefresh is the cost per node event (connect, disconnect,
// tags, services) when the host set does not change.
func BenchmarkServiceRefresh(b *testing.B) {
	for _, n := range []int{1000, 3000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s := benchServiceState(b, n)

			b.ReportAllocs()

			for b.Loop() {
				s.refreshServiceHostsLocked()
			}
		})
	}
}

// BenchmarkServiceRefreshHostChange is the cost per node event that
// changes the host set, which walks every online viewer.
func BenchmarkServiceRefreshHostChange(b *testing.B) {
	for _, n := range []int{1000, 3000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s := benchServiceState(b, n)

			b.ReportAllocs()

			for b.Loop() {
				s.services.index.Store(nil)
				s.refreshServiceHostsLocked()
			}
		})
	}
}

// BenchmarkServiceRebalance is the cost of one rebalance round when the
// clients are already balanced.
func BenchmarkServiceRebalance(b *testing.B) {
	for _, n := range []int{1000, 3000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s := benchServiceState(b, n)
			s.cfg.Services.Rebalance = types.ServicesRebalanceConfig{Interval: 1, MovesPerHostPerMinute: 1}

			b.ReportAllocs()

			for b.Loop() {
				s.rebalanceServicesLocked()
			}
		})
	}
}

// BenchmarkServiceRoutesForPeers is the service part of building one
// client's full map: serviceRoutesForPeer for every peer.
func BenchmarkServiceRoutesForPeers(b *testing.B) {
	for _, n := range []int{1000, 3000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s := benchServiceState(b, n)

			viewer, ok := s.nodeStore.GetNode(types.NodeID(n)) //nolint:gosec // small bench IDs
			require.True(b, ok)

			matchers, err := s.polMan.MatchersForNode(viewer)
			require.NoError(b, err)

			peers := s.nodeStore.ListPeers(viewer.ID())

			b.ReportAllocs()

			for b.Loop() {
				for _, p := range peers.All() {
					s.serviceRoutesForPeer(viewer, p, matchers)
				}
			}
		})
	}
}
