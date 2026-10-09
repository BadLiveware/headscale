package state

import (
	"cmp"
	"maps"
	"math"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// visibleTo returns a function that reports whether viewer sees an active
// host, from the host's sorted peers.
func (idx *serviceHostIndex) visibleTo(viewer types.NodeID) func(types.NodeID) bool {
	return func(host types.NodeID) bool {
		_, ok := slices.BinarySearch(idx.hostPeers[host], viewer)
		return ok
	}
}

// assign records that viewer keeps host for the service although its
// rendezvous choice differs.
func (idx *serviceHostIndex) assign(name tailcfg.ServiceName, viewer, host types.NodeID) {
	if idx.assigned[name] == nil {
		idx.assigned[name] = map[types.NodeID]types.NodeID{}
	}

	idx.assigned[name][viewer] = host
}

// hostFor returns the host viewer uses for the service: its assigned host
// while that host is active and visible to viewer, else its rendezvous
// choice. A nil index has no host.
func (idx *serviceHostIndex) hostFor(viewer types.NodeID, name tailcfg.ServiceName) (types.NodeID, bool) {
	if idx == nil {
		return 0, false
	}

	hosts := idx.hosts[name]
	visible := idx.visibleTo(viewer)

	if h, ok := idx.assigned[name][viewer]; ok && slices.Contains(hosts, h) && visible(h) {
		return h, true
	}

	return chooseServiceHost(viewer, hosts, visible)
}

// nextServiceHost returns the host a viewer uses after a change of the
// active hosts. It keeps the current host while that host is active and
// visible: moving a client resets its open connections. Otherwise, and
// always when follow is set (the startup grace), it is the rendezvous
// choice.
func nextServiceHost(
	viewer, current types.NodeID,
	hasCurrent bool,
	hosts []types.NodeID,
	visible func(types.NodeID) bool,
	follow bool,
) (types.NodeID, bool) {
	if !follow && hasCurrent && slices.Contains(hosts, current) && visible(current) {
		return current, true
	}

	return chooseServiceHost(viewer, hosts, visible)
}

// serviceClient is one viewer's assigned host and its rendezvous target.
type serviceClient struct {
	viewer types.NodeID
	from   types.NodeID
	to     types.NodeID
}

// withinTolerance reports whether every host's count is within tolerance of
// its rendezvous share, rounded up so a small share allows one client.
func withinTolerance(actual, target map[types.NodeID]int, tolerance float64) bool {
	for _, h := range slices.Collect(maps.Keys(actual)) {
		allowed := int(math.Ceil(tolerance * float64(target[h])))
		if diff := actual[h] - target[h]; diff > allowed || -diff > allowed {
			return false
		}
	}

	for h, want := range target {
		allowed := int(math.Ceil(tolerance * float64(want)))
		if want-actual[h] > allowed {
			return false
		}
	}

	return true
}

// planRebalance picks the clients to move to their rendezvous target, at
// most perHost from each host, only from hosts that have more clients than
// their share, the most loaded first, and stops once every host is within
// tolerance. It returns the moves in a stable order.
func planRebalance(clients []serviceClient, budget func(types.NodeID) int, tolerance float64) []serviceClient {
	actual := map[types.NodeID]int{}
	target := map[types.NodeID]int{}

	var candidates []serviceClient

	for _, c := range clients {
		actual[c.from]++
		target[c.to]++

		if c.from != c.to {
			candidates = append(candidates, c)
		}
	}

	if withinTolerance(actual, target, tolerance) {
		return nil
	}

	slices.SortFunc(candidates, func(a, b serviceClient) int {
		return cmp.Or(
			cmp.Compare(actual[b.from]-target[b.from], actual[a.from]-target[a.from]),
			cmp.Compare(a.viewer, b.viewer),
		)
	})

	taken := map[types.NodeID]int{}

	var moves []serviceClient

	for _, c := range candidates {
		if withinTolerance(actual, target, tolerance) {
			break
		}

		if taken[c.from] >= budget(c.from) || actual[c.from] <= target[c.from] {
			continue
		}

		actual[c.from]--
		actual[c.to]++
		taken[c.from]++

		moves = append(moves, c)
	}

	return moves
}

// rebalanceCreditEpsilon absorbs float rounding, so ten rounds of 0.1
// credit make one move.
const rebalanceCreditEpsilon = 1e-9

// rebalanceBudget adds one round of credit to every active host and
// returns how many whole moves each host may give up this round. The rate
// is moves_per_host_per_minute × interval, and the fraction carries over
// between rounds, so a short interval does not exceed the configured rate.
// The credit is capped at one round (at least one move), so a host does
// not save up a burst while nothing needs moving.
func (sv *services) rebalanceBudget(
	cfg types.ServicesRebalanceConfig,
	hosts map[types.NodeID][]tailcfg.ServiceName,
) func(types.NodeID) int {
	perRound := float64(cfg.MovesPerHostPerMinute) * cfg.Interval.Minutes()
	limit := math.Max(1, perRound)

	credit := make(map[types.NodeID]float64, len(hosts))
	for h := range hosts {
		credit[h] = math.Min(limit, sv.credit[h]+perRound)
	}

	sv.credit = credit

	return func(h types.NodeID) int {
		return int(credit[h] + rebalanceCreditEpsilon)
	}
}

// RebalanceServices moves a bounded number of clients towards their
// rendezvous host, after a host joined. Clients keep their host otherwise,
// so without it a joining host would only get new clients. It reports
// whether it queued changes; the callbacks of [State.OnServiceHostsMoved]
// are run, so the caller need not dispatch.
func (s *State) RebalanceServices() bool {
	if s.cfg.Services.Rebalance.Interval <= 0 || s.followRendezvous() {
		return false
	}

	if !s.rebalanceServicesLocked() {
		return false
	}

	s.notifyServiceMoves()

	return true
}

// rebalanceServicesLocked plans and applies one round. Only clients with an
// assignment differ from their rendezvous host, so a round without
// assignments costs nothing, and a round over an index that was balanced
// in the last round is skipped.
func (s *State) rebalanceServicesLocked() bool {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	idx := s.services.index.Load()
	if idx == nil || idx == s.services.balanced || !hasAssignments(idx) {
		return false
	}

	budget := s.services.rebalanceBudget(s.cfg.Services.Rebalance, idx.byNode)
	nodes := s.nodeStore.ListNodes()

	next := &serviceHostIndex{
		hosts:     idx.hosts,
		byNode:    idx.byNode,
		hostPeers: idx.hostPeers,
		assigned:  make(map[tailcfg.ServiceName]map[types.NodeID]types.NodeID, len(idx.assigned)),
	}

	for name, viewers := range idx.assigned {
		next.assigned[name] = maps.Clone(viewers)
	}

	moved := map[types.NodeID][]types.NodeID{}

	for _, name := range slices.Sorted(maps.Keys(idx.assigned)) {
		if len(idx.assigned[name]) == 0 || len(idx.hosts[name]) < 2 {
			continue
		}

		var clients []serviceClient

		for _, viewer := range nodes.All() {
			if !viewer.Online() || !s.mayReachService(viewer, name) {
				continue
			}

			from, ok := idx.hostFor(viewer.ID(), name)
			if !ok {
				continue
			}

			to, _ := chooseServiceHost(viewer.ID(), idx.hosts[name], idx.visibleTo(viewer.ID()))
			clients = append(clients, serviceClient{viewer: viewer.ID(), from: from, to: to})
		}

		for _, m := range planRebalance(clients, budget, s.cfg.Services.Rebalance.Tolerance) {
			s.services.credit[m.from]--
			delete(next.assigned[name], m.viewer)
			moved[m.viewer] = append(moved[m.viewer], m.from, m.to)
		}
	}

	if len(moved) == 0 {
		s.services.balanced = idx

		return false
	}

	s.services.index.Store(next)

	queued := make([]change.Change, 0, len(moved))

	for _, viewer := range slices.Sorted(maps.Keys(moved)) {
		c := change.PeersChanged("service rebalance", moved[viewer]...)
		c.TargetNode = viewer
		queued = append(queued, c)
	}

	log.Debug().Int("viewers.moved", len(queued)).Msg("service clients rebalanced")

	s.queueServiceMoves(queued)

	return true
}

func hasAssignments(idx *serviceHostIndex) bool {
	for _, viewers := range idx.assigned {
		if len(viewers) > 0 {
			return true
		}
	}

	return false
}
