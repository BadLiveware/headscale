package state

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestChooseServiceHostSpreadAndMovement(t *testing.T) {
	const (
		viewers   = 3000
		firstHost = types.NodeID(100_000)
	)

	hosts := []types.NodeID{firstHost, firstHost + 1, firstHost + 2, firstHost + 3}
	allPeers := slices.Clone(hosts)

	before := make(map[types.NodeID]types.NodeID, viewers)
	count := map[types.NodeID]int{}

	for v := range types.NodeID(viewers) {
		h, ok := chooseServiceHost(v+1, hosts, sees(allPeers))
		require.True(t, ok)

		before[v+1] = h
		count[h]++
	}

	// Even spread: each host within 15% of the mean.
	mean := viewers / len(hosts)
	for _, h := range hosts {
		assert.InDelta(t, mean, count[h], float64(mean)*0.15, "host %d has %d viewers", h, count[h])
	}

	// Minimal movement: removing a host moves only its viewers.
	leaving := hosts[1]
	remaining := slices.DeleteFunc(slices.Clone(hosts), func(h types.NodeID) bool { return h == leaving })

	for v, old := range before {
		h, ok := chooseServiceHost(v, remaining, sees(allPeers))
		require.True(t, ok)

		if old != leaving {
			assert.Equal(t, old, h, "viewer %d moved although its host stayed", v)
		} else {
			assert.NotEqual(t, leaving, h)
		}
	}

	// A returning host gets back exactly its viewers.
	for v, old := range before {
		h, _ := chooseServiceHost(v, hosts, sees(allPeers))
		assert.Equal(t, old, h)
	}
}

func TestChooseServiceHostOnlyVisibleHosts(t *testing.T) {
	hosts := []types.NodeID{10, 11, 12}

	_, ok := chooseServiceHost(1, hosts, sees([]types.NodeID{2, 3}))
	assert.False(t, ok, "a viewer that sees no host gets none")

	h, ok := chooseServiceHost(1, hosts, sees([]types.NodeID{11}))
	require.True(t, ok)
	assert.Equal(t, types.NodeID(11), h, "only a visible host can be chosen")
}

func TestDeriveServiceHosts(t *testing.T) {
	online := func(id types.NodeID, tags []string, services ...string) *types.Node {
		return &types.Node{
			ID:                 id,
			Tags:               tags,
			IsOnline:           new(true),
			AdvertisedServices: services,
		}
	}

	gw := []string{"tag:grafana"}

	expired := online(4, gw, "svc:grafana")
	expired.Expiry = new(time.Now().Add(-time.Hour))

	offline := online(5, gw, "svc:grafana")
	offline.IsOnline = new(false)

	nodes := types.Nodes{
		online(1, gw, "svc:grafana", "svc:gitea"),
		online(2, gw, "svc:grafana"),
		online(3, []string{"tag:gitea"}, "svc:grafana"),
		expired,
		offline,
		online(6, gw),
	}

	approve := func(n types.NodeView) []tailcfg.ServiceName {
		if n.HasTag("tag:grafana") {
			return []tailcfg.ServiceName{"svc:grafana", "svc:gitea"}
		}

		return nil
	}

	vips := serviceVIPMap{
		"svc:grafana": {netip.MustParseAddr("100.64.0.100")},
	}

	idx := deriveServiceHosts(views.SliceOf(nodes.ViewSlice().AsSlice()), approve, vips)

	assert.Equal(t, serviceHostMap{"svc:grafana": {1, 2}}, idx.hosts,
		"only online, unexpired, approved, advertising hosts of services with VIPs")
	assert.Equal(t, []tailcfg.ServiceName{"svc:grafana"}, idx.byNode[1])
}
