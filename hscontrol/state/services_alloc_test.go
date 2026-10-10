package state

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
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

const allocPolicyOneService = `{
	"tagOwners": {"tag:grafana": ["alloc@"]},
	"autoApprovers": {"services": {"svc:grafana": ["tag:grafana"]}},
	"grants": [{"src": ["alloc@"], "dst": ["svc:grafana"], "ip": ["tcp:443"]}]
}`

// allocTestConfig has room for exactly two IPv4 addresses and no IPv6. A
// node of user alloc takes one of them, so the policies' grants have a
// source.
func allocTestConfig(t *testing.T) *types.Config {
	t.Helper()

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	small := netip.MustParsePrefix("100.64.0.0/30")
	cfg.PrefixV4 = &small
	cfg.PrefixV6 = nil

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("alloc")
	database.CreateRegisteredNodeForTest(user, "alloc-node")
	require.NoError(t, database.Close())

	return cfg
}

// grantedDsts returns the destination addresses of the compiled filter.
func grantedDsts(s *State) []string {
	filter, _ := s.polMan.Filter()

	var dsts []string

	for _, rule := range filter {
		for _, d := range rule.DstPorts {
			dsts = append(dsts, d.IP)
		}
	}

	return dsts
}

// TestServiceVIPAllocationFailureKeepsReload checks that a policy reload
// whose VIP allocation fails still completes: it returns the policy change
// and no error, the new policy is in effect, and the services without VIPs
// grant nothing (fail closed).
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
	require.Empty(t, grantedDsts(s), "services without VIPs grant nothing")
}

// TestServiceVIPAllocationFailureKeepsStartup checks that Headscale starts
// when the stored policy defines a service the address pool has no room
// for; the service that has VIPs keeps them and its grant.
func TestServiceVIPAllocationFailureKeepsStartup(t *testing.T) {
	cfg := allocTestConfig(t)

	s, err := NewState(cfg)
	require.NoError(t, err)

	_, err = s.SetPolicyInDB(allocPolicyOneService)
	require.NoError(t, err)
	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	grafana := s.ServiceVIPs("svc:grafana")
	require.Len(t, grafana, 1, "svc:grafana takes the last address")
	require.Equal(t, []string{grafana[0].String()}, grantedDsts(s), "the grant reaches the VIP")

	_, err = s.SetPolicyInDB(allocPolicyTwoServices)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s, err = NewState(cfg)
	require.NoError(t, err, "Headscale starts although svc:gitea gets no VIPs")
	t.Cleanup(func() { _ = s.Close() })

	require.Equal(t, grafana, s.ServiceVIPs("svc:grafana"), "stored VIPs are kept")
	require.Empty(t, s.ServiceVIPs("svc:gitea"))
	require.Equal(t, []string{grafana[0].String()}, grantedDsts(s), "only the service with VIPs is granted")
}

// failingVIPsPolicy fails the first SetServiceVIPs call.
type failingVIPsPolicy struct {
	policy.PolicyManager

	calls int
}

func (p *failingVIPsPolicy) SetServiceVIPs(vips map[tailcfg.ServiceName][]netip.Addr) (bool, error) {
	p.calls++
	if p.calls == 1 {
		return false, errTestSetVIPs
	}

	return p.PolicyManager.SetServiceVIPs(vips)
}

var errTestSetVIPs = errors.New("test: SetServiceVIPs fails")

// TestServiceVIPsRetriedAfterPolicyError checks that VIPs the policy
// manager failed to take are given to it again on the next policy load,
// although nothing new was allocated.
func TestServiceVIPsRetriedAfterPolicyError(t *testing.T) {
	cfg := allocTestConfig(t)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	wrapped := &failingVIPsPolicy{PolicyManager: s.polMan}
	s.polMan = wrapped

	_, err = s.SetPolicyInDB(allocPolicyTwoServices)
	require.NoError(t, err)

	_, err = s.ReloadPolicy()
	require.NoError(t, err, "a failed SetServiceVIPs is logged, not returned")
	require.Equal(t, 1, wrapped.calls)

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	require.Equal(t, 2, wrapped.calls, "the next load gives the VIPs again")

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	require.Equal(t, 2, wrapped.calls, "once given, they are not given again")
}

// TestServiceVIPsNotAllocatedByPolicyCheck checks that SetPolicy, which
// the API calls to check a policy before storing it, allocates no VIPs;
// ReloadPolicy does once the policy is stored.
func TestServiceVIPsNotAllocatedByPolicyCheck(t *testing.T) {
	cfg := allocTestConfig(t)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(allocPolicyOneService))
	require.NoError(t, err)

	stored, err := s.db.ListServices()
	require.NoError(t, err)
	require.Empty(t, stored, "a checked policy uses up no addresses")
	require.Empty(t, s.ServiceVIPs("svc:grafana"))

	_, err = s.SetPolicyInDB(allocPolicyOneService)
	require.NoError(t, err)
	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	require.Len(t, s.ServiceVIPs("svc:grafana"), 1, "the stored policy gets its VIPs")
}
