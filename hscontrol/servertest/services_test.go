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

// TestServiceVIPs checks the traffic half of Tailscale Services: the
// service gets one VIP per family; each client carries the VIPs on exactly
// one host peer, chosen per client; a client moves when its host withdraws
// or goes offline, and other clients do not move; a node without an
// approved tag never carries the VIPs; a node without access gets neither
// the VIPs nor the name.
func TestServiceVIPs(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithMagicDNS("headscale.net"))
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
