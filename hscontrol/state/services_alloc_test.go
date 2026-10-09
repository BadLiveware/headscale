package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const allocPolicyNoService = `{
	"tagOwners": {"tag:grafana": ["alloc@"]},
	"acls": [{"action": "accept", "src": ["alloc@"], "dst": ["alloc@:*"]}]
}`

const allocPolicyTwoServices = `{
	"tagOwners": {"tag:grafana": ["alloc@"]},
	"autoApprovers": {"services": {
		"svc:grafana": ["tag:grafana"],
		"svc:gitea": ["tag:grafana"]
	}},
	"grants": [{"src": ["alloc@"], "dst": ["svc:grafana", "svc:gitea"], "ip": ["tcp:443"]}]
}`

const allocPolicyThreeServices = `{
	"tagOwners": {"tag:grafana": ["alloc@"]},
	"autoApprovers": {"services": {
		"svc:grafana": ["tag:grafana"],
		"svc:gitea": ["tag:grafana"],
		"svc:wiki": ["tag:grafana"]
	}},
	"grants": [{"src": ["alloc@"], "dst": ["svc:grafana", "svc:gitea", "svc:wiki"], "ip": ["tcp:443"]}]
}`

// allocTestConfig has room for exactly two IPv4 addresses and no IPv6.
func allocTestConfig(t *testing.T) *types.Config {
	t.Helper()

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	small := netip.MustParsePrefix("100.64.0.0/30")
	cfg.PrefixV4 = &small
	cfg.PrefixV6 = nil

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	database.CreateUserForTest("alloc")
	require.NoError(t, database.Close())

	return cfg
}

// TestServiceVIPAllocationFailureKeepsReload checks that a policy reload
// whose VIP allocation fails still completes: it returns the policy change
// and no error, the new policy is in effect, and the service without VIPs
// resolves to nothing (fails closed).
func TestServiceVIPAllocationFailureKeepsReload(t *testing.T) {
	cfg := allocTestConfig(t)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicyInDB(allocPolicyNoService)
	require.NoError(t, err)
	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	for {
		_, _, err := s.ipAlloc.Next()
		if err != nil {
			break
		}
	}

	_, err = s.SetPolicyInDB(allocPolicyTwoServices)
	require.NoError(t, err)

	cs, err := s.ReloadPolicy()
	require.NoError(t, err, "a failed VIP allocation must not fail the reload")
	require.NotEmpty(t, cs, "the reload still publishes the policy change")

	require.Equal(t, []tailcfg.ServiceName{"svc:gitea", "svc:grafana"}, s.polMan.ServiceNames())
	require.Empty(t, s.ServiceVIPs("svc:grafana"))

	filter, _ := s.polMan.Filter()
	require.Empty(t, filter, "a service without VIPs grants nothing")
}

// TestServiceVIPAllocationFailureKeepsStartup checks that Headscale starts
// when the stored policy defines a service the address pool has no room
// for; the other services keep their VIPs.
func TestServiceVIPAllocationFailureKeepsStartup(t *testing.T) {
	cfg := allocTestConfig(t)

	s, err := NewState(cfg)
	require.NoError(t, err)

	_, err = s.SetPolicyInDB(allocPolicyTwoServices)
	require.NoError(t, err)
	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	grafana := s.ServiceVIPs("svc:grafana")
	require.Len(t, grafana, 1, "the two services use up the pool")
	require.Len(t, s.ServiceVIPs("svc:gitea"), 1)

	_, err = s.SetPolicyInDB(allocPolicyThreeServices)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s, err = NewState(cfg)
	require.NoError(t, err, "Headscale starts although svc:wiki gets no VIPs")
	t.Cleanup(func() { _ = s.Close() })

	require.Equal(t, grafana, s.ServiceVIPs("svc:grafana"), "stored VIPs are kept")
	require.Empty(t, s.ServiceVIPs("svc:wiki"))
}
