package v2

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

const servicesTestPolicy = `{
	"tagOwners": {
		"tag:gw-cca": ["user@"],
		"tag:gw-other": ["user@"],
		"tag:client": ["user@"]
	},
	"autoApprovers": {
		"services": {
			"svc:cca": ["tag:gw-cca"]
		}
	},
	"grants": [
		{"src": ["tag:client"], "dst": ["svc:cca"], "ip": ["tcp:443"]}
	]
}`

var (
	testVIP4 = netip.MustParseAddr("100.64.0.100")
	testVIP6 = netip.MustParseAddr("fd7a:115c:a1e0::100")
)

func TestServicesValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		wantErr string
	}{
		{
			name:   "grant-to-defined-service",
			policy: servicesTestPolicy,
		},
		{
			name: "acl-to-defined-service-with-port",
			policy: `{
				"tagOwners": {"tag:gw": ["user@"]},
				"autoApprovers": {"services": {"svc:cca": ["tag:gw"]}},
				"acls": [{"action": "accept", "src": ["user@"], "dst": ["svc:cca:443"]}]
			}`,
		},
		{
			name: "undefined-service",
			policy: `{
				"tagOwners": {"tag:gw": ["user@"]},
				"grants": [{"src": ["user@"], "dst": ["svc:cca"], "ip": ["443"]}]
			}`,
			wantErr: "service not defined",
		},
		{
			name: "service-as-source",
			policy: `{
				"tagOwners": {"tag:gw": ["user@"]},
				"autoApprovers": {"services": {"svc:cca": ["tag:gw"]}},
				"grants": [{"src": ["svc:cca"], "dst": ["*"], "ip": ["443"]}]
			}`,
			wantErr: "only be a destination",
		},
		{
			name: "undefined-host-tag",
			policy: `{
				"autoApprovers": {"services": {"svc:cca": ["tag:gw"]}}
			}`,
			wantErr: "tag not found",
		},
		{
			name: "no-host-tags",
			policy: `{
				"autoApprovers": {"services": {"svc:cca": []}}
			}`,
			wantErr: "lists no tags",
		},
		{
			name: "invalid-service-name",
			policy: `{
				"tagOwners": {"tag:gw": ["user@"]},
				"autoApprovers": {"services": {"svc:Bad_Name": ["tag:gw"]}}
			}`,
			wantErr: "invalid service name",
		},
		{
			name: "user-as-host",
			policy: `{
				"autoApprovers": {"services": {"svc:cca": ["user@"]}}
			}`,
			wantErr: "tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unmarshalPolicy([]byte(tt.policy))
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// servicesTestNodes returns two hosts of svc:cca, a host with another
// tag, an allowed client, and an untagged user node.
func servicesTestNodes(users types.Users) []*types.Node {
	return []*types.Node{
		{ID: 1, Tags: []string{"tag:gw-cca"}, IPv4: ap("100.64.0.1"), IPv6: ap("fd7a:115c:a1e0::1")},
		{ID: 2, Tags: []string{"tag:gw-cca"}, IPv4: ap("100.64.0.2"), IPv6: ap("fd7a:115c:a1e0::2")},
		{ID: 3, Tags: []string{"tag:gw-other"}, IPv4: ap("100.64.0.3"), IPv6: ap("fd7a:115c:a1e0::3")},
		{ID: 4, Tags: []string{"tag:client"}, IPv4: ap("100.64.0.4"), IPv6: ap("fd7a:115c:a1e0::4")},
		{
			ID:     5,
			UserID: new(users[0].ID),
			User:   &users[0],
			IPv4:   ap("100.64.0.5"),
			IPv6:   ap("fd7a:115c:a1e0::5"),
		},
	}
}

func newServicesTestManager(t *testing.T) (*PolicyManager, []*types.Node) {
	t.Helper()

	users := types.Users{{ID: 1, Name: "user"}}
	nodes := servicesTestNodes(users)

	pm, err := NewPolicyManager([]byte(servicesTestPolicy), users, types.Nodes(nodes).ViewSlice())
	require.NoError(t, err)

	assert.Equal(t, []tailcfg.ServiceName{"svc:cca"}, pm.ServiceNames())

	changed, err := pm.SetServiceVIPs(map[tailcfg.ServiceName][]netip.Addr{
		"svc:cca": {testVIP4, testVIP6},
	})
	require.NoError(t, err)
	assert.True(t, changed, "setting the VIPs changes the compiled policy")

	return pm, nodes
}

func TestServiceHostCapability(t *testing.T) {
	pm, nodes := newServicesTestManager(t)

	for _, n := range nodes {
		caps := pm.NodeCapMap(n.ID)
		raw, ok := caps[nodecap.ServiceHost]

		if !slices.Contains(n.Tags, "tag:gw-cca") {
			assert.False(t, ok, "node %d must not be a service host", n.ID)
			continue
		}

		require.True(t, ok, "node %d is an approved host", n.ID)
		require.Len(t, raw, 1, "the client accepts exactly one service-host value")

		var got tailcfg.ServiceIPMappings
		require.NoError(t, json.Unmarshal([]byte(raw[0]), &got))
		assert.Equal(t, tailcfg.ServiceIPMappings{"svc:cca": {testVIP4, testVIP6}}, got)
	}

	assert.Equal(t,
		[]tailcfg.ServiceName{"svc:cca"},
		pm.NodeServices(nodes[0].View()),
	)
	assert.Empty(t, pm.NodeServices(nodes[2].View()), "another tag is not approved")
	assert.Empty(t, pm.NodeServices(nodes[4].View()), "untagged nodes never host services")
}

func TestServiceFilterRules(t *testing.T) {
	pm, nodes := newServicesTestManager(t)

	vipDsts := []tailcfg.NetPortRange{
		{IP: testVIP4.String(), Ports: tailcfg.PortRange{First: 443, Last: 443}},
		{IP: testVIP6.String(), Ports: tailcfg.PortRange{First: 443, Last: 443}},
	}

	for _, n := range nodes {
		rules, err := pm.FilterForNode(n.View())
		require.NoError(t, err)

		var dsts []tailcfg.NetPortRange
		for _, r := range rules {
			dsts = append(dsts, r.DstPorts...)
		}

		if slices.Contains(n.Tags, "tag:gw-cca") {
			assert.ElementsMatch(t, vipDsts, dsts, "host %d gets the rule for the VIPs", n.ID)

			require.Len(t, rules, 1)
			assert.ElementsMatch(t, []string{"100.64.0.4", "fd7a:115c:a1e0::4"}, rules[0].SrcIPs)

			continue
		}

		assert.Empty(t, dsts, "node %d hosts nothing and gets no VIP rule", n.ID)
	}
}

func TestServicePeerMap(t *testing.T) {
	pm, nodes := newServicesTestManager(t)

	peers := pm.BuildPeerMap(types.Nodes(nodes).ViewSlice())

	assert.ElementsMatch(t, []types.NodeID{4}, peers[1], "host 1 sees the allowed client")
	assert.ElementsMatch(t, []types.NodeID{4}, peers[2], "host 2 sees the allowed client")
	assert.ElementsMatch(t, []types.NodeID{1, 2}, peers[4], "the client sees both hosts")
	assert.Empty(t, peers[3], "a node with another tag is not a host")
	assert.Empty(t, peers[5], "a node without a grant sees no host")
}

func TestServiceVIPsKeptAcrossPolicyReload(t *testing.T) {
	pm, nodes := newServicesTestManager(t)

	_, err := pm.SetPolicy([]byte(servicesTestPolicy))
	require.NoError(t, err)

	rules, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)
	require.Len(t, rules, 1, "the VIPs survive a policy reload")
}
