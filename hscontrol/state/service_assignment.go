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

// hostFor returns the host viewer uses for the service: its assigned host
// while that host is active and visible to viewer, else its rendezvous
// choice. A nil index has no host.
func (idx *serviceHostIndex) hostFor(
	viewer types.NodeID,
	name tailcfg.ServiceName,
	peers []types.NodeID,
) (types.NodeID, bool) {
	if idx == nil {
		return 0, false
	}

	hosts := idx.hosts[name]

	if h, ok := idx.assigned[name][viewer]; ok && slices.Contains(hosts, h) {
		if _, visible := slices.BinarySearch(peers, h); visible {
			return h, true
		}
	}

	return chooseServiceHost(viewer, hosts, peers)
}

// nextServiceHost returns the host a viewer uses after a change of the
// active hosts. It keeps the current host while that host is active and
// visible: moving a client resets its open connections. Otherwise, and
// always when follow is set (the startup grace), it is the rendezvous
// choice.
func nextServiceHost(
	viewer, current types.NodeID,
	hasCurrent bool,
	hosts, peers []types.NodeID,
	follow bool,
) (types.NodeID, bool) {
	if !follow && hasCurrent && slices.Contains(hosts, current) {
		if _, visible := slices.BinarySearch(peers, current); visible {
			return current, true
		}
	}

	return chooseServiceHost(viewer, hosts, peers)
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
func planRebalance(clients []serviceClient, perHost int, tolerance float64) []serviceClient {
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

		if taken[c.from] >= perHost || actual[c.from] <= target[c.from] {
			continue
		}

		actual[c.from]--
		actual[c.to]++
		taken[c.from]++

		moves = append(moves, c)
	}

	return moves
}

// rebalanceMovesPerHost is how many clients one rebalance may take from a
// host: the per-minute rate spread over the interval, at least one.
func rebalanceMovesPerHost(cfg types.ServicesRebalanceConfig) int {
	return max(1, int(float64(cfg.MovesPerHostPerMinute)*cfg.Interval.Minutes()))
}

// RebalanceServices moves a bounded number of clients towards their
// rendezvous host, after a host joined. Clients keep their host otherwise,
// so without it a joining host would only get new clients. It reports
// whether it queued changes; the callers of [State.OnServiceHostsMoved]
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

func (s *State) rebalanceServicesLocked() bool {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	idx := s.services.index.Load()
	if idx == nil {
		return false
	}

	perHost := rebalanceMovesPerHost(s.cfg.Services.Rebalance)
	nodes := s.nodeStore.ListNodes()

	next := &serviceHostIndex{
		hosts:    idx.hosts,
		byNode:   idx.byNode,
		assigned: make(map[tailcfg.ServiceName]map[types.NodeID]types.NodeID, len(idx.assigned)),
	}

	for name, viewers := range idx.assigned {
		next.assigned[name] = maps.Clone(viewers)
	}

	peersOf := map[types.NodeID][]types.NodeID{}
	moved := map[types.NodeID][]types.NodeID{}

	for _, name := range slices.Sorted(maps.Keys(idx.hosts)) {
		if len(idx.hosts[name]) < 2 {
			continue
		}

		var clients []serviceClient

		for _, viewer := range nodes.All() {
			if !viewer.Online() {
				continue
			}

			peers, ok := peersOf[viewer.ID()]
			if !ok {
				peers = s.nodeStore.ListPeerIDs(viewer.ID())
				peersOf[viewer.ID()] = peers
			}

			from, ok := idx.hostFor(viewer.ID(), name, peers)
			if !ok {
				continue
			}

			to, _ := chooseServiceHost(viewer.ID(), idx.hosts[name], peers)
			clients = append(clients, serviceClient{viewer: viewer.ID(), from: from, to: to})
		}

		for _, m := range planRebalance(clients, perHost, s.cfg.Services.Rebalance.Tolerance) {
			if next.assigned[name] == nil {
				next.assigned[name] = map[types.NodeID]types.NodeID{}
			}

			next.assigned[name][m.viewer] = m.to
			moved[m.viewer] = append(moved[m.viewer], m.from, m.to)
		}
	}

	s.services.index.Store(next)

	if len(moved) == 0 {
		return false
	}

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
