package servertest_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
)

const (
	serviceName    = tailcfg.ServiceName("svc:cca")
	serviceDNSName = "cca.headscale.net"
	serviceWait    = 15 * time.Second
)

const servicesPolicy = `{
	"tagOwners": {
		"tag:gw-cca": ["svc-user@"],
		"tag:rogue": ["svc-user@"],
		"tag:client": ["svc-user@"]
	},
	"autoApprovers": {"services": {"svc:cca": ["tag:gw-cca"]}},
	"grants": [
		{"src": ["tag:client"], "dst": ["svc:cca"], "ip": ["tcp:80"]},
		{"src": ["tag:client"], "dst": ["tag:rogue"], "ip": ["*"]}
	]
}`

// serviceVIPsOf returns the VIPs of svc:cca from a host's service-host
// capability.
func serviceVIPsOf(nm *netmap.NetworkMap) []netip.Addr {
	if nm == nil || !nm.SelfNode.Valid() {
		return nil
	}

	raw, ok := nm.SelfNode.CapMap().GetOk(nodecap.ServiceHost)
	if !ok || raw.Len() != 1 {
		return nil
	}

	var m tailcfg.ServiceIPMappings
	if err := json.Unmarshal([]byte(raw.At(0)), &m); err != nil { //nolint:noinlineerr
		return nil
	}

	return m[serviceName]
}

// vipCarriers returns the names of the peers whose AllowedIPs in nm hold
// any of vips.
func vipCarriers(nm *netmap.NetworkMap, vips []netip.Addr) []string {
	if nm == nil {
		return nil
	}

	var names []string

	for _, p := range nm.Peers {
		for _, aip := range p.AllowedIPs().All() {
			if aip.IsSingleIP() && slices.Contains(vips, aip.Addr()) {
				names = append(names, p.Hostinfo().Hostname())

				break
			}
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// carrier returns the single peer that carries both VIPs in nm, or "".
func carrier(nm *netmap.NetworkMap, vips []netip.Addr) string {
	names := vipCarriers(nm, vips)
	if len(names) != 1 {
		return ""
	}

	var n int

	for _, p := range nm.Peers {
		if p.Hostinfo().Hostname() != names[0] {
			continue
		}

		for _, aip := range p.AllowedIPs().All() {
			if aip.IsSingleIP() && slices.Contains(vips, aip.Addr()) {
				n++
			}
		}
	}

	if n != len(vips) {
		return ""
	}

	return names[0]
}

func serviceRecords(nm *netmap.NetworkMap) []netip.Addr {
	return claimedAddrs(nm, serviceDNSName)
}

// TestServiceVIPs checks the traffic half of Tailscale Services during the
// startup grace, when clients follow rendezvous: the service gets one VIP
// per family; each client carries the VIPs on exactly one host peer, chosen
// per client; a client moves when its host withdraws or goes offline, and
// other clients do not move; a node without an
// approved tag never carries the VIPs; a node without access gets neither
// the VIPs nor the name.
func TestServiceVIPs(t *testing.T) {
	t.Parallel()

	// Within the startup grace clients follow rendezvous at once, which is
	// what this test checks; TestServiceStickyRebalance covers the rest.
	srv := servertest.NewServer(t,
		servertest.WithMagicDNS("headscale.net"),
		servertest.WithServices(types.ServicesConfig{StartupGrace: time.Hour}),
	)
	user := srv.CreateUser(t, "svc-user")
	reloadPolicy(t, srv, servicesPolicy)

	vips := srv.State().ServiceVIPs(serviceName)
	require.Len(t, vips, 2, "the service gets an IPv4 and an IPv6 VIP")

	newClient := func(name string, tags ...string) *servertest.TestClient {
		opts := []servertest.ClientOption{servertest.WithUser(user)}
		if len(tags) > 0 {
			opts = append(opts, servertest.WithTags(tags...))
		}

		return servertest.NewClient(t, srv, name, opts...)
	}

	gw1 := newClient("gw1", "tag:gw-cca")
	gw2 := newClient("gw2", "tag:gw-cca")
	rogue := newClient("rogue", "tag:rogue")
	outsider := newClient("outsider")

	const numClients = 8

	clients := make([]*servertest.TestClient, numClients)
	for i := range clients {
		clients[i] = newClient(fmt.Sprintf("client%d", i), "tag:client")
	}

	for _, c := range clients {
		c.WaitForPeers(t, 3, 10*time.Second)
	}

	for _, gw := range []*servertest.TestClient{gw1, gw2} {
		gw.WaitForCondition(t, gw.Name+" gets the service-host capability", serviceWait,
			func(nm *netmap.NetworkMap) bool { return slices.Equal(serviceVIPsOf(nm), vips) })
	}

	rogue.WaitForCondition(t, "rogue is no service host", serviceWait,
		func(nm *netmap.NetworkMap) bool { return nm != nil && len(serviceVIPsOf(nm)) == 0 })

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" resolves the service name to the VIPs", serviceWait,
			func(nm *netmap.NetworkMap) bool { return slices.Equal(serviceRecords(nm), sorted(vips)) })
	}

	gw1.AdvertiseServices(t, serviceName)
	gw2.AdvertiseServices(t, serviceName)
	rogue.AdvertiseServices(t, serviceName)

	require.Eventually(t, func() bool {
		return len(srv.State().ServiceHosts(serviceName)) == 2
	}, serviceWait, 50*time.Millisecond, "gw1 and gw2 become active hosts, the rogue node does not")

	choice := map[string]string{}

	for _, c := range clients {
		self := c.Netmap().SelfNode.ID()

		hostID, ok := srv.State().ServiceHostFor(types.NodeID(self), serviceName) //nolint:gosec // test node IDs are small
		require.True(t, ok, "%s has a host", c.Name)

		host, ok := srv.State().GetNodeByID(hostID)
		require.True(t, ok)

		want := host.Hostname()

		c.WaitForCondition(t, c.Name+" carries the VIPs on its host "+want, serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == want })

		choice[c.Name] = want
	}

	perHost := map[string]int{}
	for _, h := range choice {
		perHost[h]++
	}

	require.Positive(t, perHost["gw1"], "clients spread over both hosts: %v", choice)
	require.Positive(t, perHost["gw2"], "clients spread over both hosts: %v", choice)

	// Drain: gw1 withdraws. Its clients move to gw2; gw2's clients keep
	// their host and get no update for it.
	updatesBefore := map[string]int{}
	for _, c := range clients {
		updatesBefore[c.Name] = c.UpdateCount()
	}

	start := time.Now()

	gw1.AdvertiseServices(t)

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" carries the VIPs on gw2", serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw2" })
	}

	t.Logf("withdraw: all clients on gw2 after %s", time.Since(start))

	require.Never(t, func() bool {
		for _, c := range clients {
			if choice[c.Name] == "gw2" && c.UpdateCount() != updatesBefore[c.Name] {
				return true
			}
		}

		return false
	}, time.Second, 100*time.Millisecond, "clients that kept gw2 get no map update")

	// gw1 advertises again: exactly its clients move back.
	gw1.AdvertiseServices(t, serviceName)

	for _, c := range clients {
		want := choice[c.Name]
		c.WaitForCondition(t, c.Name+" returns to "+want, serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == want })
	}

	// gw2 goes offline: its clients move to gw1 after the offline grace.
	start = time.Now()

	gw2.Disconnect(t)

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" carries the VIPs on gw1", 30*time.Second,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw1" })
	}

	t.Logf("offline: all clients on gw1 after %s", time.Since(start))

	// A node without a grant to the service sees neither VIPs nor name.
	nm := outsider.Netmap()
	require.Empty(t, vipCarriers(nm, vips), "outsider must not carry the VIPs")
	require.Empty(t, serviceRecords(nm), "outsider must not resolve the service")
}

func sorted(addrs []netip.Addr) []netip.Addr {
	out := slices.Clone(addrs)
	slices.SortFunc(out, netip.Addr.Compare)

	return out
}

// TestServiceVIPsForClaimedNames checks that a hostnameClaims name keeps
// answering with the claiming host's own addresses when the service has
// VIPs (only <label>.<base_domain> answers with the VIPs), and that a
// service keeps its VIPs when the policy drops and restores it.
func TestServiceVIPsForClaimedNames(t *testing.T) {
	t.Parallel()

	const claimed = "cca.gw.example.com"

	pol := `{
		"tagOwners": {"tag:gw-cca": ["svc-user@"]},
		"autoApprovers": {"services": {"svc:cca": ["tag:gw-cca"]}},
		"hostnameClaims": {"*.gw.example.com": ["tag:gw-cca"]},
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]
	}`

	srv := servertest.NewServer(t, servertest.WithMagicDNS("headscale.net"))
	user := srv.CreateUser(t, "svc-user")
	reloadPolicy(t, srv, pol)

	vips := srv.State().ServiceVIPs(serviceName)
	require.Len(t, vips, 2)

	gw := servertest.NewClient(t, srv, "gw", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))
	viewer := servertest.NewClient(t, srv, "viewer", servertest.WithUser(user))

	viewer.WaitForPeers(t, 1, 10*time.Second)

	gw.AdvertiseServices(t, serviceName)

	require.Eventually(t, func() bool {
		return len(srv.State().ServiceHosts(serviceName)) == 1
	}, serviceWait, 50*time.Millisecond, "gw becomes an active host")

	viewer.WaitForCondition(t, "the claimed name answers with the host's addresses", serviceWait,
		func(nm *netmap.NetworkMap) bool { return slices.Equal(claimedAddrs(nm, claimed), selfAddrs(t, gw)) })

	viewer.WaitForCondition(t, "the base-domain name answers with the VIPs", serviceWait,
		func(nm *netmap.NetworkMap) bool { return slices.Equal(serviceRecords(nm), sorted(vips)) })

	viewer.WaitForCondition(t, "the viewer carries the VIPs on gw", serviceWait,
		func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw" })

	reloadPolicy(t, srv, `{
		"tagOwners": {"tag:gw-cca": ["svc-user@"]},
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]
	}`)

	viewer.WaitForCondition(t, "a dropped service loses its route and name", serviceWait,
		func(nm *netmap.NetworkMap) bool {
			return len(vipCarriers(nm, vips)) == 0 && len(serviceRecords(nm)) == 0
		})

	reloadPolicy(t, srv, pol)

	require.Equal(t, vips, srv.State().ServiceVIPs(serviceName), "a restored service gets its old VIPs")

	viewer.WaitForCondition(t, "the restored service is reachable again", serviceWait,
		func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw" })
}

// lastHostSetup starts a server with one active host of svc:cca and a
// client that reaches the service through it.
func lastHostSetup(t *testing.T) (*servertest.TestServer, *servertest.TestClient, *servertest.TestClient, []netip.Addr) {
	t.Helper()

	srv := servertest.NewServer(t, servertest.WithMagicDNS("headscale.net"))
	user := srv.CreateUser(t, "svc-user")
	reloadPolicy(t, srv, servicesPolicy)

	vips := srv.State().ServiceVIPs(serviceName)
	require.Len(t, vips, 2)

	gw := servertest.NewClient(t, srv, "gw", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))
	client := servertest.NewClient(t, srv, "client", servertest.WithUser(user), servertest.WithTags("tag:client"))

	client.WaitForPeers(t, 1, 10*time.Second)

	gw.AdvertiseServices(t, serviceName)

	client.WaitForCondition(t, "client carries the VIPs on gw", serviceWait,
		func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw" })
	client.WaitForCondition(t, "client resolves the service", serviceWait,
		func(nm *netmap.NetworkMap) bool { return slices.Equal(serviceRecords(nm), sorted(vips)) })

	return srv, gw, client, vips
}

func nodeIDOf(c *servertest.TestClient) types.NodeID {
	return types.NodeID(c.Netmap().SelfNode.ID()) //nolint:gosec // test node IDs are small
}

// TestServiceLastHostLosesTag checks that when the only host loses its
// approved tag, the client drops the VIP route and the host drops its
// service-host capability; the service name stays, since the policy still
// defines the service. Getting the tag back restores both.
func TestServiceLastHostLosesTag(t *testing.T) {
	t.Parallel()

	srv, gw, client, vips := lastHostSetup(t)

	_, c, err := srv.State().SetNodeTags(nodeIDOf(gw), []string{"tag:rogue"})
	require.NoError(t, err)
	srv.App.Change(c)

	client.WaitForCondition(t, "client drops the VIP route of the unapproved host", serviceWait,
		func(nm *netmap.NetworkMap) bool { return len(vipCarriers(nm, vips)) == 0 })
	gw.WaitForCondition(t, "gw drops its service-host capability", serviceWait,
		func(nm *netmap.NetworkMap) bool { return nm != nil && len(serviceVIPsOf(nm)) == 0 })
	require.Equal(t, sorted(vips), serviceRecords(client.Netmap()), "the defined service keeps its name")

	_, c, err = srv.State().SetNodeTags(nodeIDOf(gw), []string{"tag:gw-cca"})
	require.NoError(t, err)
	srv.App.Change(c)

	client.WaitForCondition(t, "client carries the VIPs on gw again", serviceWait,
		func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw" })
}

// TestServiceLastHostExpires checks that the client drops the VIP route
// when the only host's key expires.
func TestServiceLastHostExpires(t *testing.T) {
	t.Parallel()

	srv, gw, client, vips := lastHostSetup(t)

	expired := time.Now().Add(-time.Minute)

	_, c, err := srv.State().SetNodeExpiry(nodeIDOf(gw), &expired)
	require.NoError(t, err)
	srv.App.Change(c)

	client.WaitForCondition(t, "client drops the VIP route of the expired host", serviceWait,
		func(nm *netmap.NetworkMap) bool { return len(vipCarriers(nm, vips)) == 0 })
}

// TestServiceApprovalMovesToAnotherTag checks that a policy change that
// approves another tag for the service takes the VIP route away from the
// only host, while the service keeps its name and VIPs.
func TestServiceApprovalMovesToAnotherTag(t *testing.T) {
	t.Parallel()

	srv, gw, client, vips := lastHostSetup(t)

	reloadPolicy(t, srv, `{
		"tagOwners": {
			"tag:gw-cca": ["svc-user@"],
			"tag:rogue": ["svc-user@"],
			"tag:client": ["svc-user@"]
		},
		"autoApprovers": {"services": {"svc:cca": ["tag:rogue"]}},
		"grants": [
			{"src": ["tag:client"], "dst": ["svc:cca"], "ip": ["tcp:80"]},
			{"src": ["tag:client"], "dst": ["tag:gw-cca"], "ip": ["*"]}
		]
	}`)

	client.WaitForCondition(t, "client drops the VIP route of the no longer approved host", serviceWait,
		func(nm *netmap.NetworkMap) bool { return len(vipCarriers(nm, vips)) == 0 })
	gw.WaitForCondition(t, "gw drops its service-host capability", serviceWait,
		func(nm *netmap.NetworkMap) bool { return nm != nil && len(serviceVIPsOf(nm)) == 0 })
	require.Equal(t, vips, srv.State().ServiceVIPs(serviceName))
	require.Equal(t, sorted(vips), serviceRecords(client.Netmap()), "the defined service keeps its name")
}

// TestServiceClientLosesAccess checks that a client whose tag change takes
// away its grant to the service drops the VIP route and the service name.
func TestServiceClientLosesAccess(t *testing.T) {
	t.Parallel()

	srv, _, client, vips := lastHostSetup(t)

	_, c, err := srv.State().SetNodeTags(nodeIDOf(client), []string{"tag:rogue"})
	require.NoError(t, err)
	srv.App.Change(c)

	client.WaitForCondition(t, "client without a grant drops the VIP route and the name", serviceWait,
		func(nm *netmap.NetworkMap) bool {
			return len(vipCarriers(nm, vips)) == 0 && len(serviceRecords(nm)) == 0
		})
}

// TestServiceStickyRebalance checks host assignment after the startup
// grace: a joining host takes no client at once; the bounded rebalance
// moves clients to it, at most one per source host per round here, until
// every client is on its rendezvous host (tolerance 0); a leaving host
// moves only its own clients.
func TestServiceStickyRebalance(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t,
		servertest.WithMagicDNS("headscale.net"),
		servertest.WithServices(types.ServicesConfig{
			Rebalance: types.ServicesRebalanceConfig{
				Interval:              time.Minute,
				MovesPerHostPerMinute: 1,
			},
		}),
	)
	user := srv.CreateUser(t, "svc-user")
	reloadPolicy(t, srv, servicesPolicy)

	vips := srv.State().ServiceVIPs(serviceName)

	gw1 := servertest.NewClient(t, srv, "gw1", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))
	gw2 := servertest.NewClient(t, srv, "gw2", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))

	const numClients = 8

	clients := make([]*servertest.TestClient, numClients)
	for i := range clients {
		clients[i] = servertest.NewClient(t, srv, fmt.Sprintf("client%d", i),
			servertest.WithUser(user), servertest.WithTags("tag:client"))
	}

	for _, c := range clients {
		c.WaitForPeers(t, 2, 10*time.Second)
	}

	gw1.AdvertiseServices(t, serviceName)

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" is on gw1, the only host", serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw1" })
	}

	updatesBefore := map[string]int{}
	for _, c := range clients {
		updatesBefore[c.Name] = c.UpdateCount()
	}

	gw2.AdvertiseServices(t, serviceName)

	require.Eventually(t, func() bool {
		return len(srv.State().ServiceHosts(serviceName)) == 2
	}, serviceWait, 50*time.Millisecond, "gw2 becomes an active host")

	require.Never(t, func() bool {
		for _, c := range clients {
			if c.UpdateCount() != updatesBefore[c.Name] {
				return true
			}
		}

		return false
	}, time.Second, 100*time.Millisecond, "a joining host takes no client at once")

	// Each round may take one client from gw1 (1 per minute, 1-minute
	// interval). Rounds continue until every client is on its target.
	rounds := 0

	for srv.State().RebalanceServices() {
		rounds++
		require.LessOrEqual(t, rounds, numClients, "the rebalance converges")
	}

	want := map[string]string{}

	for _, c := range clients {
		self := nodeIDOf(c)

		hostID, ok := srv.State().ServiceHostFor(self, serviceName)
		require.True(t, ok)

		host, ok := srv.State().GetNodeByID(hostID)
		require.True(t, ok)

		want[c.Name] = host.Hostname()

		c.WaitForCondition(t, c.Name+" ends on "+want[c.Name], serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == want[c.Name] })
	}

	onGW2 := 0

	for _, h := range want {
		if h == "gw2" {
			onGW2++
		}
	}

	require.Equal(t, onGW2, rounds, "one client moved per round")
	require.Positive(t, onGW2, "the rebalance gave gw2 clients: %v", want)
	t.Logf("rebalance: %d of %d clients moved to gw2 in %d rounds", onGW2, numClients, rounds)

	// gw2 leaves: only its clients move, at once.
	updatesBefore = map[string]int{}
	for _, c := range clients {
		updatesBefore[c.Name] = c.UpdateCount()
	}

	gw2.AdvertiseServices(t)

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" is on gw1", serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw1" })
	}

	require.Never(t, func() bool {
		for _, c := range clients {
			if want[c.Name] == "gw1" && c.UpdateCount() != updatesBefore[c.Name] {
				return true
			}
		}

		return false
	}, time.Second, 100*time.Millisecond, "clients that were on gw1 get no update")
}

// TestServiceStartupGraceSpreadsClients checks that hosts that come up one
// after another during the startup grace, as after a Headscale restart, do
// not leave every client on the first one.
func TestServiceStartupGraceSpreadsClients(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t,
		servertest.WithMagicDNS("headscale.net"),
		servertest.WithServices(types.ServicesConfig{StartupGrace: time.Hour}),
	)
	user := srv.CreateUser(t, "svc-user")
	reloadPolicy(t, srv, servicesPolicy)

	vips := srv.State().ServiceVIPs(serviceName)

	gw1 := servertest.NewClient(t, srv, "gw1", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))
	gw2 := servertest.NewClient(t, srv, "gw2", servertest.WithUser(user), servertest.WithTags("tag:gw-cca"))

	const numClients = 8

	clients := make([]*servertest.TestClient, numClients)
	for i := range clients {
		clients[i] = servertest.NewClient(t, srv, fmt.Sprintf("client%d", i),
			servertest.WithUser(user), servertest.WithTags("tag:client"))
	}

	for _, c := range clients {
		c.WaitForPeers(t, 2, 10*time.Second)
	}

	gw1.AdvertiseServices(t, serviceName)

	for _, c := range clients {
		c.WaitForCondition(t, c.Name+" is on gw1 first", serviceWait,
			func(nm *netmap.NetworkMap) bool { return carrier(nm, vips) == "gw1" })
	}

	gw2.AdvertiseServices(t, serviceName)

	require.Eventually(t, func() bool {
		onGW2 := 0

		for _, c := range clients {
			if carrier(c.Netmap(), vips) == "gw2" {
				onGW2++
			}
		}

		return onGW2 > 0
	}, serviceWait, 50*time.Millisecond, "without any rebalance round, gw2 gets its rendezvous share at once")
}
