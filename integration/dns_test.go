package integration

import (
	"encoding/json"
	"fmt"
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

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("magicdns"))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			assert.Equal(t, peer.Hostname()+".headscale.net.", peerFQDN)

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				command := []string{
					"tailscale",
					"ip", peerFQDN,
				}
				result, _, err := client.Execute(command)
				assert.NoError(ct, err, "Failed to execute resolve/ip command %s from %s", peerFQDN, client.Hostname())

				ips, err := peer.IPs()
				assert.NoError(ct, err, "Failed to get IPs for %s", peer.Hostname())

				for _, ip := range ips {
					assert.Contains(ct, result, ip.String(), "IP %s should be found in DNS resolution result from %s to %s", ip.String(), client.Hostname(), peer.Hostname())
				}
			}, integrationutil.StatusReadyTimeout, 2*time.Second)
		}
	}
}

func TestResolveMagicDNSExtraRecordsPath(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	const erPath = "/tmp/extra_records.json"

	extraRecords := make([]tailcfg.DNSRecord, 0, 2)
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "test.myvpn.example.com",
		Type:  "A",
		Value: "6.6.6.6",
	})
	b, _ := json.Marshal(extraRecords) //nolint:errchkjson

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithPackages("python3", "curl", "bind-tools"),
	},
		hsic.WithTestName("extrarecords"),
		hsic.WithConfigEnv(map[string]string{
			// Disable global nameservers to make the test run offline.
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			"HEADSCALE_DNS_EXTRA_RECORDS_PATH": erPath,
		}),
		hsic.WithFileInContainer(erPath, b),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
	}

	hs, err := scenario.Headscale()
	require.NoError(t, err)

	// Write the file directly into place from the docker API.
	b0, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "2.2.2.2",
		},
	})

	err = hs.WriteFile(erPath, b0)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "2.2.2.2")
	}

	// Write a new file and move it to the path to ensure the reload
	// works when a file is moved atomically into place.
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "otherrecord.myvpn.example.com",
		Type:  "A",
		Value: "7.7.7.7",
	})
	b2, _ := json.Marshal(extraRecords) //nolint:errchkjson

	err = hs.WriteFile(erPath+"2", b2)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"mv", erPath + "2", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
		assertCommandOutputContains(t, client, []string{"dig", "otherrecord.myvpn.example.com"}, "7.7.7.7")
	}

	// Write a new file and copy it to the path to ensure the reload
	// works when a file is copied into place.
	b3, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "copy.myvpn.example.com",
			Type:  "A",
			Value: "8.8.8.8",
		},
	})

	err = hs.WriteFile(erPath+"3", b3)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"cp", erPath + "3", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}

	// Write in place to ensure pipe like behaviour works
	b4, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "9.9.9.9",
		},
	})
	command := []string{"echo", fmt.Sprintf("'%s'", string(b4)), ">", erPath}
	_, err = hs.Execute([]string{"bash", "-c", strings.Join(command, " ")})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "9.9.9.9")
	}

	// Delete the file and create a new one to ensure it is picked up again.
	_, err = hs.Execute([]string{"rm", erPath})
	require.NoError(t, err)

	// The same paths should still be available as it is not cleared on delete.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, client := range allClients {
			result, _, err := client.Execute([]string{"dig", "docker.myvpn.example.com"})
			assert.NoError(ct, err)
			assert.Contains(ct, result, "9.9.9.9")
		}
	}, integrationutil.ScaledTimeout(10*time.Second), 1*time.Second)

	// Write a new file, the backoff mechanism should make the filewatcher pick it up
	// again.
	err = hs.WriteFile(erPath, b3)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}
}

// TestNodeClaimedHostnames checks that tagged nodes can claim a hostname by
// advertising a service (`tailscale serve advertise`), that other nodes
// resolve the name to every online node that claims it, and that a node is
// removed when it drains (`tailscale serve drain`) or goes offline. A node
// whose tag the policy does not authorise cannot claim the name.
func TestNodeClaimedHostnames(t *testing.T) {
	IntegrationSkip(t)

	const (
		gatewayUser = "gateway"
		rogueUser   = "rogue"
		clientUser  = "client"
		service     = "svc:cca"
		claimedName = "cca.gw.example.com"
	)

	spec := ScenarioSpec{Users: []string{gatewayUser, rogueUser, clientUser}}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:gateway": policyv2.Owners{usernameOwner(gatewayUser + "@")},
			"tag:rogue":   policyv2.Owners{usernameOwner(rogueUser + "@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		HostnameClaims: policyv2.HostnameClaims{
			"*.gw.example.com": {"tag:gateway"},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("claimedhosts"),
		hsic.WithConfigEnv(map[string]string{
			// Disable global nameservers to make the test run offline.
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	nodesPerUser := []struct {
		user  string
		count int
		tags  []string
	}{
		{user: gatewayUser, count: 2, tags: []string{"tag:gateway"}},
		{user: rogueUser, count: 1, tags: []string{"tag:rogue"}},
		{user: clientUser, count: 1},
	}

	for _, n := range nodesPerUser {
		u, err := scenario.CreateUser(n.user)
		require.NoError(t, err)

		err = scenario.CreateTailscaleNodesInUser(n.user, tsic.VersionHead, n.count,
			tsic.WithNetwork(scenario.Networks()[0]),
			tsic.WithPackages("bind-tools"),
		)
		require.NoError(t, err)

		key, err := scenario.CreatePreAuthKey(mustParseID(u.Id), true, false)
		if len(n.tags) > 0 {
			key, err = scenario.CreatePreAuthKeyWithTags(mustParseID(u.Id), true, false, n.tags)
		}

		require.NoError(t, err)

		err = scenario.RunTailscaleUp(n.user, headscale.GetEndpoint(), key.Key)
		require.NoError(t, err)
	}

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	gateways, err := scenario.ListTailscaleClients(gatewayUser)
	requireNoErrListClients(t, err)

	rogues, err := scenario.ListTailscaleClients(rogueUser)
	requireNoErrListClients(t, err)

	clients, err := scenario.ListTailscaleClients(clientUser)
	requireNoErrListClients(t, err)

	client := clients[0]

	for _, node := range append(slices.Clone(gateways), rogues...) {
		_, _, err := node.Execute([]string{"tailscale", "serve", "advertise", service})
		require.NoErrorf(t, err, "%s advertising %s", node.Hostname(), service)
	}

	addrsOf := func(nodes ...TailscaleClient) []string {
		var addrs []string

		for _, node := range nodes {
			ips, err := node.IPs()
			require.NoError(t, err)

			for _, ip := range ips {
				addrs = append(addrs, ip.String())
			}
		}

		return addrs
	}

	// requireResolves waits until the client resolves the claimed name, A
	// and AAAA, to exactly want, and returns how long that took.
	requireResolves := func(want []string, timeout time.Duration, msg string) time.Duration {
		t.Helper()

		start := time.Now()

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			stdout, _, err := client.Execute([]string{
				"dig", "+short", claimedName, "A", claimedName, "AAAA",
			})
			assert.NoError(c, err)
			assert.ElementsMatch(c, want, strings.Fields(stdout))
		}, timeout, 500*time.Millisecond, msg)

		return time.Since(start)
	}

	requireResolves(addrsOf(gateways...), integrationutil.ScaledTimeout(30*time.Second),
		"client resolves the claimed name to both gateways and not to the rogue node")

	_, _, err = gateways[0].Execute([]string{"tailscale", "serve", "drain", service})
	require.NoError(t, err)

	took := requireResolves(addrsOf(gateways[1]), integrationutil.ScaledTimeout(10*time.Second),
		"client stops resolving the claimed name to the drained gateway")
	t.Logf("drained gateway left the answers after %s", took)

	_, _, err = gateways[0].Execute([]string{"tailscale", "serve", "advertise", service})
	require.NoError(t, err)

	requireResolves(addrsOf(gateways...), integrationutil.ScaledTimeout(10*time.Second),
		"client resolves the claimed name to both gateways again")

	err = gateways[1].Down()
	require.NoError(t, err)

	// Headscale waits up to 10 s for a reconnect before it marks a node
	// offline.
	took = requireResolves(addrsOf(gateways[0]), integrationutil.ScaledTimeout(30*time.Second),
		"client stops resolving the claimed name to the offline gateway")
	t.Logf("offline gateway left the answers after %s", took)
}
