package integration

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// serviceOldClientVersion is an older supported client that consumes the
// service. It predates the client route manager (v1.103), so it routes
// the VIP through the WireGuard cryptokey table, and it is at least v1.94,
// so it needs no --accept-routes.
const serviceOldClientVersion = "1.102"

// TestServiceVIPs checks Tailscale Services with virtual IPs (VIPs) end to
// end with stock clients. Two gateways host svc:grafana with `tailscale serve
// --service`; each client reaches the service at its VIP and its name and
// lands on one gateway; a gateway that drains or stops loses its clients
// to the other gateway; a node whose tag is not approved never serves the
// service; a node without a grant to the service cannot reach it.
func TestServiceVIPs(t *testing.T) {
	IntegrationSkip(t)

	const (
		gatewayUser  = "gateway"
		rogueUser    = "rogue"
		clientUser   = "client"
		outsiderUser = "outsider"
		service      = "svc:grafana"
		servicePort  = 80
		serviceLabel = "grafana"
		pollInterval = 250 * time.Millisecond
		headClients  = 4
		allClients   = headClients + 1
		hostsAndSpy  = 3
	)

	spec := ScenarioSpec{Users: []string{gatewayUser, rogueUser, clientUser, outsiderUser}}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	tcp80 := []policyv2.ProtocolPort{{
		Protocol: policyv2.ProtocolNameTCP,
		Ports:    []tailcfg.PortRange{{First: servicePort, Last: servicePort}},
	}}

	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:grafana": policyv2.Owners{usernameOwner(gatewayUser + "@")},
			"tag:rogue":   policyv2.Owners{usernameOwner(rogueUser + "@")},
		},
		AutoApprovers: policyv2.AutoApproverPolicy{
			Services: policyv2.ServiceApprovers{service: {"tag:grafana"}},
		},
		Grants: []policyv2.Grant{
			{
				Sources:           policyv2.Aliases{usernamep(clientUser + "@")},
				Destinations:      policyv2.Aliases{new(policyv2.Service(service))},
				InternetProtocols: tcp80,
			},
			{
				// The rogue node is a peer of the clients, so the test
				// shows that being visible is not enough to get the VIP.
				Sources:           policyv2.Aliases{usernamep(clientUser + "@")},
				Destinations:      policyv2.Aliases{tagp("tag:rogue")},
				InternetProtocols: tcp80,
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("servicevips"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			// Clients follow rendezvous at once during the startup
			// grace. This test checks what stock clients do with the
			// VIPs; the sticky assignment and its rebalance are covered
			// by servertest (TestServiceStickyRebalance).
			"HEADSCALE_SERVICES_STARTUP_GRACE": "1h",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	nodes := []struct {
		user    string
		version string
		count   int
		tags    []string
	}{
		{user: gatewayUser, version: tsic.VersionHead, count: 2, tags: []string{"tag:grafana"}},
		{user: rogueUser, version: tsic.VersionHead, count: 1, tags: []string{"tag:rogue"}},
		{user: clientUser, version: tsic.VersionHead, count: headClients},
		{user: clientUser, version: serviceOldClientVersion, count: 1},
		{user: outsiderUser, version: tsic.VersionHead, count: 1},
	}

	userIDs := map[string]uint64{}

	for _, n := range nodes {
		if _, ok := userIDs[n.user]; !ok {
			u, err := scenario.CreateUser(n.user)
			require.NoError(t, err)

			userIDs[n.user] = mustParseID(u.Id)
		}

		err = scenario.CreateTailscaleNodesInUser(n.user, n.version, n.count,
			tsic.WithNetwork(scenario.Networks()[0]),
		)
		require.NoError(t, err)
	}

	for user, id := range userIDs {
		key, err := scenario.CreatePreAuthKey(id, true, false)
		if user == gatewayUser {
			key, err = scenario.CreatePreAuthKeyWithTags(id, true, false, []string{"tag:grafana"})
		}

		if user == rogueUser {
			key, err = scenario.CreatePreAuthKeyWithTags(id, true, false, []string{"tag:rogue"})
		}

		require.NoError(t, err)

		err = scenario.RunTailscaleUp(user, headscale.GetEndpoint(), key.Key)
		require.NoError(t, err)
	}

	list := func(user string) []TailscaleClient {
		c, err := scenario.ListTailscaleClients(user)
		requireNoErrListClients(t, err)

		slices.SortFunc(c, func(a, b TailscaleClient) int { return strings.Compare(a.Hostname(), b.Hostname()) })

		return c
	}

	gateways := list(gatewayUser)
	rogue := list(rogueUser)[0]
	clients := list(clientUser)
	outsider := list(outsiderUser)[0]

	// Peers: a client sees both gateways and the rogue node; a gateway and
	// the rogue node see every client; the outsider sees nobody.
	syncTimeout := integrationutil.ScaledTimeout(60 * time.Second)
	for _, c := range clients {
		require.NoError(t, c.WaitForPeers(hostsAndSpy, syncTimeout, time.Second))
	}

	for _, h := range append(slices.Clone(gateways), rogue) {
		require.NoError(t, h.WaitForPeers(allClients, syncTimeout, time.Second))
	}

	for _, h := range append(slices.Clone(gateways), rogue) {
		_, _, err := h.Execute([]string{
			"tailscale", "serve", "--service=" + service, "--bg",
			fmt.Sprintf("--http=%d", servicePort), "text:" + h.Hostname(),
		})
		require.NoErrorf(t, err, "%s serving %s", h.Hostname(), service)
	}

	status := clients[0].MustStatus()
	serviceFQDN := serviceLabel + "." + status.CurrentTailnet.MagicDNSSuffix

	// The VIPs come from a gateway's service-host capability, as the
	// gateway's own `tailscale serve status` shows them.
	var vips []netip.Addr

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := gateways[0].Netmap()
		assert.NoError(c, err)

		vips = nm.GetVIPServiceIPMap()[tailcfg.ServiceName(service)]
		assert.Len(c, vips, 2, "the gateway knows one IPv4 and one IPv6 VIP")
	}, integrationutil.ScaledTimeout(30*time.Second), time.Second)
	require.Len(t, vips, 2)

	t.Logf("service %s: VIPs %v, name %s", service, vips, serviceFQDN)

	urlOf := func(addr netip.Addr) string {
		return fmt.Sprintf("http://%s/", netip.AddrPortFrom(addr, servicePort))
	}

	// fetch returns the body served at url, or "" when the request fails.
	// Busybox wget is in every client image.
	fetch := func(c TailscaleClient, url string) string {
		stdout, _, err := c.Execute([]string{"wget", "-q", "-T", "2", "-O", "-", url})
		if err != nil {
			return ""
		}

		return strings.TrimSpace(stdout)
	}

	// servedBy waits until client reaches the service over both VIPs and,
	// for HEAD clients, over its name, at one host in want. It returns the
	// host and when the wait ended.
	servedBy := func(c TailscaleClient, want []string, timeout time.Duration, msg string) (string, time.Time) {
		t.Helper()

		var host string

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			got := []string{fetch(c, urlOf(vips[0])), fetch(c, urlOf(vips[1]))}
			if c.Version() == tsic.VersionHead {
				got = append(got, fetch(c, fmt.Sprintf("http://%s/", serviceFQDN)))
			}

			host = got[0]
			assert.Containsf(ct, want, host, "%s reached %q", c.Hostname(), got)

			for _, g := range got {
				assert.Equalf(ct, host, g, "%s: every address of the service reaches one host: %q", c.Hostname(), got)
			}
		}, timeout, pollInterval, msg)

		return host, time.Now()
	}

	gatewayNames := []string{gateways[0].Hostname(), gateways[1].Hostname()}

	choice := map[string]string{}

	for _, c := range clients {
		host, _ := servedBy(c, gatewayNames, integrationutil.ScaledTimeout(60*time.Second),
			c.Hostname()+" reaches the service on a gateway")
		choice[c.Hostname()] = host
	}

	// A client keeps its host: rendezvous hashing per client, not per
	// request.
	for _, c := range clients {
		for range 3 {
			assert.Equal(t, choice[c.Hostname()], fetch(c, urlOf(vips[0])), "%s keeps its host", c.Hostname())
		}
	}

	perHost := map[string][]string{}
	for client, host := range choice {
		perHost[host] = append(perHost[host], client)
	}

	t.Logf("distribution: %v", perHost)

	// Never the rogue node, and never more than one peer per client
	// holding the VIPs (checked on the HEAD clients' netmaps).
	for _, c := range clients {
		if c.Version() != tsic.VersionHead {
			continue
		}

		nm, err := c.Netmap()
		require.NoError(t, err)

		var holders []string

		for _, p := range nm.Peers {
			for _, aip := range p.AllowedIPs().All() {
				if aip.IsSingleIP() && slices.Contains(vips, aip.Addr()) {
					holders = append(holders, p.Hostinfo().Hostname())

					break
				}
			}
		}

		assert.Equal(t, []string{choice[c.Hostname()]}, holders,
			"%s holds the VIPs on exactly its chosen gateway", c.Hostname())
	}

	// The outsider has no grant: no VIP route, no name, no answer.
	assert.Empty(t, fetch(outsider, urlOf(vips[0])), "outsider cannot reach the VIP")

	stdout, _, _ := outsider.Execute([]string{"tailscale", "dns", "status", "--json"})
	assert.NotContains(t, stdout, serviceFQDN, "outsider does not get the service name")

	// Drain the gateway with the most clients.
	drained, kept := gateways[0], gateways[1]
	if len(perHost[kept.Hostname()]) > len(perHost[drained.Hostname()]) {
		drained, kept = kept, drained
	}

	drainStart := time.Now()

	_, _, err = drained.Execute([]string{"tailscale", "serve", "drain", service})
	require.NoError(t, err)

	var worstDrain time.Duration

	for _, c := range clients {
		_, done := servedBy(c, []string{kept.Hostname()}, integrationutil.ScaledTimeout(20*time.Second),
			c.Hostname()+" moves off the drained gateway")
		if choice[c.Hostname()] == drained.Hostname() {
			worstDrain = max(worstDrain, done.Sub(drainStart))
		}
	}

	t.Logf("drain: every client served by %s within %s", kept.Hostname(), worstDrain)

	_, _, err = drained.Execute([]string{"tailscale", "serve", "advertise", service})
	require.NoError(t, err)

	for _, c := range clients {
		servedBy(c, []string{choice[c.Hostname()]}, integrationutil.ScaledTimeout(20*time.Second),
			c.Hostname()+" returns to its gateway")
	}

	// Stop a gateway cleanly. Headscale marks it offline after its 10 s
	// reconnect grace and moves its clients.
	stopped, other := gateways[0], gateways[1]
	if len(perHost[other.Hostname()]) > len(perHost[stopped.Hostname()]) {
		stopped, other = other, stopped
	}

	stopStart := time.Now()

	require.NoError(t, stopped.Down())

	var worstStop time.Duration

	for _, c := range clients {
		_, done := servedBy(c, []string{other.Hostname()}, integrationutil.ScaledTimeout(40*time.Second),
			c.Hostname()+" moves off the stopped gateway")
		if choice[c.Hostname()] == stopped.Hostname() {
			worstStop = max(worstStop, done.Sub(stopStart))
		}
	}

	t.Logf("stop: every client served by %s within %s", other.Hostname(), worstStop)
}
