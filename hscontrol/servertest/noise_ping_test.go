package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Short ping settings keep these tests fast; production defaults are in
// config-example.yaml.
const (
	testPingAfterIdle = 2 * time.Second
	testPingTimeout   = 1 * time.Second

	// offlineGrace is the reconnect wait in poll.go before a node whose
	// connection ended is marked offline.
	offlineGrace = 10 * time.Second
)

func nodeID(t *testing.T, c *servertest.TestClient) types.NodeID {
	t.Helper()

	nm := c.Netmap()
	require.NotNil(t, nm, "%s has no netmap", c.Name)

	return types.NodeID(nm.SelfNode.ID()) //nolint:gosec // test node IDs are small
}

func online(srv *servertest.TestServer, id types.NodeID) bool {
	node, ok := srv.State().GetNodeByID(id)

	return ok && node.Online()
}

// TestNoisePingFindsCutNode checks that a node whose network path is cut,
// without the connection being closed, goes offline within the ping
// settings plus the reconnect grace.
func TestNoisePingFindsCutNode(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithNoisePing(testPingAfterIdle, testPingTimeout))
	user := srv.CreateUser(t, "ping-user")

	cut := servertest.NewClient(t, srv, "cut", servertest.WithUser(user))
	peer := servertest.NewClient(t, srv, "peer", servertest.WithUser(user))

	cut.WaitForPeers(t, 1, 10*time.Second)
	peer.WaitForPeers(t, 1, 10*time.Second)

	id := nodeID(t, cut)
	require.True(t, online(srv, id))

	start := time.Now()

	cut.CutNetwork()

	bound := testPingAfterIdle + testPingTimeout + offlineGrace + 5*time.Second
	assert.Eventually(t, func() bool { return !online(srv, id) }, bound, 100*time.Millisecond,
		"cut node must go offline within %s", bound)

	t.Logf("cut node offline after %s (ping after %s idle, %s timeout, %s grace)",
		time.Since(start).Round(100*time.Millisecond), testPingAfterIdle, testPingTimeout, offlineGrace)
}

// TestNoisePingDisabledKeepsCutNodeOnline is the baseline: without the
// ping check, a cut node stays online, because nothing fails on the
// server side until TCP gives up.
func TestNoisePingDisabledKeepsCutNodeOnline(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "noping-user")

	cut := servertest.NewClient(t, srv, "cut", servertest.WithUser(user))
	peer := servertest.NewClient(t, srv, "peer", servertest.WithUser(user))

	cut.WaitForPeers(t, 1, 10*time.Second)
	peer.WaitForPeers(t, 1, 10*time.Second)

	id := nodeID(t, cut)

	cut.CutNetwork()

	window := testPingAfterIdle + testPingTimeout + offlineGrace + 5*time.Second
	assert.Never(t, func() bool { return !online(srv, id) }, window, 500*time.Millisecond,
		"without the ping check the cut node stays online")
}

// TestNoisePingKeepsIdleClientOnline checks that a healthy client that
// sends nothing stays connected across many ping rounds: it answers each
// PING, so the server never closes its connection.
func TestNoisePingKeepsIdleClientOnline(t *testing.T) {
	t.Parallel()

	const idle = 1 * time.Second

	srv := servertest.NewServer(t, servertest.WithNoisePing(idle, idle))
	user := srv.CreateUser(t, "idle-user")

	a := servertest.NewClient(t, srv, "idle-a", servertest.WithUser(user))
	b := servertest.NewClient(t, srv, "idle-b", servertest.WithUser(user))

	a.WaitForPeers(t, 1, 10*time.Second)
	b.WaitForPeers(t, 1, 10*time.Second)

	ids := []types.NodeID{nodeID(t, a), nodeID(t, b)}

	epochs := make(map[types.NodeID]uint64, len(ids))
	for _, id := range ids {
		node, ok := srv.State().GetNodeByID(id)
		require.True(t, ok)

		epochs[id] = node.SessionEpoch()
	}

	// Fifteen ping rounds with no other traffic.
	assert.Never(t, func() bool {
		return !online(srv, ids[0]) || !online(srv, ids[1])
	}, 15*idle, 100*time.Millisecond, "idle healthy clients stay online")

	for _, id := range ids {
		node, ok := srv.State().GetNodeByID(id)
		require.True(t, ok)
		assert.Equal(t, epochs[id], node.SessionEpoch(), "node %d kept its session, no reconnect", id)
	}
}
