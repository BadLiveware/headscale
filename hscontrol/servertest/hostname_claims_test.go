package servertest_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

const hostnameClaimsPolicy = `{
	"tagOwners": {
		"tag:gateway": ["claims-user@"],
		"tag:rogue": ["claims-user@"]
	},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	"hostnameClaims": {
		"*.gw.example.com": ["tag:gateway"]
	}
}`

const claimedName = "cca.gw.example.com"

// claimedAddrs returns the addresses nm's DNS config gives name.
func claimedAddrs(nm *netmap.NetworkMap, name string) []netip.Addr {
	if nm == nil {
		return nil
	}

	var addrs []netip.Addr

	for _, r := range nm.DNS.ExtraRecords {
		if r.Name == name {
			addrs = append(addrs, netip.MustParseAddr(r.Value))
		}
	}

	slices.SortFunc(addrs, netip.Addr.Compare)

	return addrs
}

// selfAddrs returns the sorted addresses of c's own node.
func selfAddrs(t *testing.T, c *servertest.TestClient) []netip.Addr {
	t.Helper()

	nm := c.Netmap()
	if nm == nil || !nm.SelfNode.Valid() {
		t.Fatalf("%s has no self node", c.Name)
	}

	var addrs []netip.Addr
	for _, p := range nm.SelfNode.Addresses().All() {
		addrs = append(addrs, p.Addr())
	}

	return addrs
}

func waitForClaim(t *testing.T, viewer *servertest.TestClient, want []netip.Addr, desc string) {
	t.Helper()

	slices.SortFunc(want, netip.Addr.Compare)

	viewer.WaitForCondition(t, desc, 15*time.Second, func(nm *netmap.NetworkMap) bool {
		return slices.Equal(claimedAddrs(nm, claimedName), want)
	})
}

// TestHostnameClaims checks the core loop of node-claimed hostnames: two
// authorised nodes claim one name and a third node resolves it to both; a
// node that withdraws, or goes offline, is removed; a node without an
// authorised tag cannot claim the name.
func TestHostnameClaims(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithMagicDNS("headscale.net"))
	user := srv.CreateUser(t, "claims-user")
	reloadPolicy(t, srv, hostnameClaimsPolicy)

	gw1 := servertest.NewClient(t, srv, "gw1", servertest.WithUser(user), servertest.WithTags("tag:gateway"))
	gw2 := servertest.NewClient(t, srv, "gw2", servertest.WithUser(user), servertest.WithTags("tag:gateway"))
	rogue := servertest.NewClient(t, srv, "rogue", servertest.WithUser(user), servertest.WithTags("tag:rogue"))
	viewer := servertest.NewClient(t, srv, "viewer", servertest.WithUser(user))

	for _, c := range []*servertest.TestClient{gw1, gw2, rogue, viewer} {
		c.WaitForPeers(t, 3, 10*time.Second)
	}

	svc := tailcfg.ServiceName("svc:cca")

	gw1.AdvertiseServices(t, svc)
	gw2.AdvertiseServices(t, svc)
	rogue.AdvertiseServices(t, svc)

	both := slices.Concat(selfAddrs(t, gw1), selfAddrs(t, gw2))
	waitForClaim(t, viewer, both, "viewer resolves the name to both gateways, not to the rogue node")

	// The claiming nodes see the records too, including their own.
	waitForClaim(t, gw1, both, "gw1 sees both gateways")

	// Draining: gw1 withdraws its claim.
	gw1.AdvertiseServices(t)
	waitForClaim(t, viewer, selfAddrs(t, gw2), "viewer drops gw1 after it withdraws")

	// gw1 claims again.
	gw1.AdvertiseServices(t, svc)
	waitForClaim(t, viewer, both, "viewer adds gw1 back")

	// gw2 goes offline. Headscale waits up to 10 s for a reconnect
	// before it marks a node offline.
	gw2.Disconnect(t)
	waitForClaim(t, viewer, selfAddrs(t, gw1), "viewer drops gw2 once it is offline")
}

// TestHostnameClaimsFollowVisibility checks that a node only receives the
// claims of nodes the policy lets it see.
func TestHostnameClaimsFollowVisibility(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithMagicDNS("headscale.net"))
	user := srv.CreateUser(t, "claims-user")
	reloadPolicy(t, srv, hostnameClaimsPolicy)

	gw := servertest.NewClient(t, srv, "gw", servertest.WithUser(user), servertest.WithTags("tag:gateway"))
	viewer := servertest.NewClient(t, srv, "viewer", servertest.WithUser(user))

	gw.WaitForPeers(t, 1, 10*time.Second)
	viewer.WaitForPeers(t, 1, 10*time.Second)

	gw.AdvertiseServices(t, "svc:cca")
	waitForClaim(t, viewer, selfAddrs(t, gw), "viewer sees the claim")

	// Only tagged nodes may talk to each other: viewer loses gw as a peer.
	reloadPolicy(t, srv, `{
		"tagOwners": {
			"tag:gateway": ["claims-user@"],
			"tag:rogue": ["claims-user@"]
		},
		"acls": [{"action": "accept", "src": ["tag:gateway"], "dst": ["tag:gateway:*"]}],
		"hostnameClaims": {"*.gw.example.com": ["tag:gateway"]}
	}`)

	waitForClaim(t, viewer, nil, "viewer no longer gets the claim of a node it cannot see")
	waitForClaim(t, gw, selfAddrs(t, gw), "gw still sees its own claim")
}
