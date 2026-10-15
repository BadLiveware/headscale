package state

import (
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const (
	testViewers   = 1200
	testFirstHost = types.NodeID(100_000)
)

func testHosts(n int) []types.NodeID {
	hosts := make([]types.NodeID, n)
	for i := range hosts {
		hosts[i] = testFirstHost + types.NodeID(i)
	}

	return hosts
}

func TestNextServiceHostKeepsHostOnJoin(t *testing.T) {
	three := testHosts(3)
	four := testHosts(4)

	for v := types.NodeID(1); v <= testViewers; v++ {
		cur, ok := chooseServiceHost(v, three, sees(four))
		require.True(t, ok)

		got, ok := nextServiceHost(v, cur, true, four, sees(four), false)
		require.True(t, ok)
		assert.Equal(t, cur, got, "a joining host takes no client at once")

		rendezvous, _ := chooseServiceHost(v, four, sees(four))
		got, _ = nextServiceHost(v, cur, true, four, sees(four), true)
		assert.Equal(t, rendezvous, got, "during the startup grace a client follows rendezvous")
	}
}

func TestNextServiceHostMovesOnlyClientsOfALeavingHost(t *testing.T) {
	four := testHosts(4)
	leaving := four[2]
	three := []types.NodeID{four[0], four[1], four[3]}

	for v := types.NodeID(1); v <= testViewers; v++ {
		cur, _ := chooseServiceHost(v, four, sees(four))

		got, ok := nextServiceHost(v, cur, true, three, sees(four), false)
		require.True(t, ok)

		if cur == leaving {
			assert.NotEqual(t, leaving, got)
		} else {
			assert.Equal(t, cur, got, "viewer %d moved although its host stayed", v)
		}
	}
}

// TestNextServiceHostStartupGrace shows why the startup grace exists:
// hosts come back one by one after a restart. Without the grace every
// client stays on the first host; with it the clients spread at once.
func TestNextServiceHostStartupGrace(t *testing.T) {
	hosts := testHosts(3)

	for _, follow := range []bool{false, true} {
		assigned := map[types.NodeID]types.NodeID{}

		for i := range hosts {
			active := hosts[:i+1]

			for v := types.NodeID(1); v <= testViewers; v++ {
				cur, has := assigned[v]
				if h, ok := nextServiceHost(v, cur, has, active, sees(hosts), follow); ok {
					assigned[v] = h
				}
			}
		}

		count := map[types.NodeID]int{}
		for _, h := range assigned {
			count[h]++
		}

		if follow {
			for _, h := range hosts {
				assert.InDelta(t, testViewers/len(hosts), count[h], testViewers*0.05, "grace: host %d", h)
			}
		} else {
			assert.Equal(t, testViewers, count[hosts[0]], "no grace: the first host back keeps everyone")
		}
	}
}

// TestPlanRebalanceAfterJoin checks the rebalance after a fourth host
// joined: every round takes at most perHost clients from each host, only
// from hosts above their share, only clients whose rendezvous host is the
// new one, and the spread ends within the tolerance.
func TestPlanRebalanceAfterJoin(t *testing.T) {
	const (
		perHost   = 2
		tolerance = 0.1
	)

	three := testHosts(3)
	four := testHosts(4)
	joined := four[3]

	assigned := map[types.NodeID]types.NodeID{}
	for v := types.NodeID(1); v <= testViewers; v++ {
		assigned[v], _ = chooseServiceHost(v, three, sees(three))
	}

	clientsNow := func() []serviceClient {
		clients := make([]serviceClient, 0, testViewers)
		for v := types.NodeID(1); v <= testViewers; v++ {
			to, _ := chooseServiceHost(v, four, sees(four))
			clients = append(clients, serviceClient{viewer: v, from: assigned[v], to: to})
		}

		return clients
	}

	rounds, total := 0, 0

	for ; rounds < testViewers; rounds++ {
		moves := planRebalance(clientsNow(), budgetOf(three, perHost), tolerance)
		if len(moves) == 0 {
			break
		}

		perSource := map[types.NodeID]int{}

		for _, m := range moves {
			assert.Equal(t, joined, m.to, "only clients that prefer the new host move")
			perSource[m.from]++
			assigned[m.viewer] = m.to
		}

		for h, n := range perSource {
			assert.LessOrEqual(t, n, perHost, "host %d lost too many clients in one round", h)
		}

		total += len(moves)
	}

	actual, target := map[types.NodeID]int{}, map[types.NodeID]int{}
	for _, c := range clientsNow() {
		actual[c.from]++
		target[c.to]++
	}

	assert.True(t, withinTolerance(actual, target, tolerance), "actual %v target %v", actual, target)

	// The new host's share is about a quarter; stopping within tolerance
	// needs a bit less than that, and never more.
	assert.LessOrEqual(t, total, target[joined])
	assert.GreaterOrEqual(t, total, target[joined]-int(float64(target[joined])*tolerance)-1)

	// Three source hosts give up to perHost each per round.
	assert.GreaterOrEqual(t, rounds, total/(perHost*len(three)))
	t.Logf("join of a 4th host: %d moves in %d rounds", total, rounds)
}

func TestPlanRebalanceNothingWithinTolerance(t *testing.T) {
	clients := []serviceClient{
		{viewer: 1, from: 10, to: 10},
		{viewer: 2, from: 10, to: 11},
		{viewer: 3, from: 11, to: 11},
	}

	assert.Empty(t, planRebalance(clients, map[types.NodeID]int{10: 5, 11: 5}, 0.5), "a spread within tolerance moves nobody")
	assert.Len(t, planRebalance(clients, map[types.NodeID]int{10: 5, 11: 5}, 0), 1, "with no tolerance the client moves to its target")
}

func TestRebalanceBudgetKeepsRate(t *testing.T) {
	hosts := map[types.NodeID][]tailcfg.ServiceName{testFirstHost: nil}

	tests := []struct {
		perMinute int
		interval  time.Duration
		rounds    int
		want      int
	}{
		{perMinute: 12, interval: 10 * time.Second, rounds: 60, want: 120},
		{perMinute: 5, interval: 10 * time.Second, rounds: 60, want: 50},
		{perMinute: 15, interval: 10 * time.Second, rounds: 60, want: 150},
		{perMinute: 6, interval: time.Second, rounds: 60, want: 6},
	}

	for _, tt := range tests {
		cfg := types.ServicesRebalanceConfig{Interval: tt.interval, MovesPerHostPerMinute: tt.perMinute}

		var sv services

		moves := 0

		for range tt.rounds {
			n := sv.rebalanceBudget(cfg, hosts)[testFirstHost]
			sv.credit[testFirstHost] -= float64(n)
			moves += n
		}

		assert.Equal(t, tt.want, moves, "%d per minute at %s, every move used", tt.perMinute, tt.interval)
	}

	// Unused whole moves are not saved up.
	var sv services

	cfg := types.ServicesRebalanceConfig{Interval: 10 * time.Second, MovesPerHostPerMinute: 12}
	for range 10 {
		sv.rebalanceBudget(cfg, hosts)
	}

	assert.Equal(t, 2, sv.rebalanceBudget(cfg, hosts)[testFirstHost], "no burst after idle rounds")
}

// TestPlanRebalanceSharesBudgetAcrossServices checks that a host serving
// two services gives up at most its budget in one round in total, not per
// service.
func TestPlanRebalanceSharesBudgetAcrossServices(t *testing.T) {
	const budget = 2

	busy, idle := types.NodeID(10), types.NodeID(11)

	clients := make([]serviceClient, 0, 10)
	for v := range types.NodeID(10) {
		clients = append(clients, serviceClient{viewer: v + 100, from: busy, to: idle})
	}

	remaining := map[types.NodeID]int{busy: budget, idle: budget}

	first := planRebalance(clients, remaining, 0)
	second := planRebalance(clients, remaining, 0)

	assert.Len(t, first, budget)
	assert.Empty(t, second, "the second service finds the host's budget used up")
}

// budgetOf gives each host the same number of moves for one round.
func budgetOf(hosts []types.NodeID, n int) map[types.NodeID]int {
	m := make(map[types.NodeID]int, len(hosts))
	for _, h := range hosts {
		m[h] = n
	}

	return m
}

// sees returns a visibility function over sorted peers.
func sees(peers []types.NodeID) func(types.NodeID) bool {
	return func(h types.NodeID) bool {
		_, ok := slices.BinarySearch(peers, h)
		return ok
	}
}

// TestRefreshLetsRebalanceLookAgain checks that a refresh, even one that
// changes no host, clears the rebalance's balanced mark: clients can come
// online or gain access without a host change.
func TestRefreshLetsRebalanceLookAgain(t *testing.T) {
	s := benchServiceState(t, 20)

	s.services.balanced = s.services.index.Load()
	s.refreshServiceHostsLocked()

	assert.Nil(t, s.services.balanced)
}

// TestOfflineAssignmentDroppedWhenHostLeaves checks that an offline
// client's sticky host is forgotten once that host leaves, so the client
// gets its rendezvous choice even if the old host is back before it.
func TestOfflineAssignmentDroppedWhenHostLeaves(t *testing.T) {
	s := benchServiceState(t, 30)

	const viewer = types.NodeID(10)

	idx := s.services.index.Load()
	target, ok := idx.hostFor(viewer, benchService)
	require.True(t, ok)

	var other types.NodeID

	for _, h := range idx.hosts[benchService] {
		if h != target {
			other = h

			break
		}
	}

	sticky := *idx
	sticky.assigned = map[tailcfg.ServiceName]map[types.NodeID]types.NodeID{}
	sticky.assign(benchService, viewer, other)
	s.services.index.Store(&sticky)

	s.nodeStore.UpdateNode(viewer, func(n *types.Node) { n.IsOnline = new(false) })

	s.nodeStore.UpdateNode(other, func(n *types.Node) { n.AdvertisedServices = nil })
	s.refreshServiceHostsLocked()

	s.nodeStore.UpdateNode(other, func(n *types.Node) { n.AdvertisedServices = []string{benchService.String()} })
	s.refreshServiceHostsLocked()

	got, ok := s.services.index.Load().hostFor(viewer, benchService)
	require.True(t, ok)
	assert.Equal(t, target, got, "the viewer's old host left; it gets its rendezvous choice")
}
