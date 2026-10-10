package state

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// serviceVIPMap maps a service to its virtual IP addresses (VIPs).
type serviceVIPMap map[tailcfg.ServiceName][]netip.Addr

// serviceHostMap maps a service to the sorted IDs of its active hosts.
type serviceHostMap map[tailcfg.ServiceName][]types.NodeID

// serviceHostIndex is the set of active service hosts, indexed both ways,
// and the clients that use another host than their rendezvous choice. It
// is immutable once stored.
type serviceHostIndex struct {
	hosts  serviceHostMap
	byNode map[types.NodeID][]tailcfg.ServiceName

	// hostPeers holds the sorted peer IDs of each active host. Peer
	// visibility is symmetric, so "viewer sees host" is a binary search
	// here instead of a copy and sort of the viewer's peers.
	hostPeers map[types.NodeID][]types.NodeID

	// peerGen is the NodeStore peer-map generation hostPeers was read at.
	// A different current generation means hostPeers may be stale, see
	// [State.reconcileServiceHosts].
	peerGen uint64

	// assigned holds, per service, the viewers that keep a host other than
	// their rendezvous choice (sticky after a host joined, until the
	// rebalance moves them). Every other viewer uses its rendezvous
	// choice, see [serviceHostIndex.hostFor].
	assigned map[tailcfg.ServiceName]map[types.NodeID]types.NodeID
}

// services holds the VIPs of Tailscale Services and which nodes host them.
//
// A client cannot fail over between two peers that carry the same VIP: its
// route table picks one peer per prefix and keeps it while the peer is
// offline. So each client gets the VIP in the AllowedIPs of exactly one
// host, chosen per client by rendezvous hashing, and Headscale moves it to
// the client's next host when that host stops hosting.
type services struct {
	// mu serialises allocation and host refreshes, so a refresh from an
	// older snapshot cannot overwrite a newer one.
	mu sync.Mutex

	vips  atomic.Pointer[serviceVIPMap]
	index atomic.Pointer[serviceHostIndex]

	pendingMu sync.Mutex
	pending   []change.Change

	movedMu sync.Mutex
	moved   []func()

	// startedAt starts the startup grace, see [State.followRendezvous].
	startedAt time.Time

	// balanced is the index the last rebalance round found nothing to
	// move in; the next rounds skip it until a refresh stores a new one.
	balanced *serviceHostIndex

	// policySynced reports whether the policy manager holds the VIPs in
	// vips; a failed SetServiceVIPs leaves it false, so the next load
	// retries. Guarded by mu.
	policySynced bool

	// credit is the fractional rebalance budget per host, see
	// [services.rebalanceBudget]. Guarded by mu.
	credit map[types.NodeID]float64
}

// serviceVIPAllocationFailures counts services the policy defines that
// got no VIPs, for example because the address pool is exhausted.
var serviceVIPAllocationFailures = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: prometheusNamespace,
	Name:      "service_vip_allocation_failures_total",
	Help:      "Total number of failed virtual IP allocations for Tailscale Services",
})

// loadServiceVIPs reads the stored VIPs on first use, allocates VIPs for
// the services the policy defines that have none yet, and gives the result
// to the policy manager when it changed. It reports whether the policy
// manager needs to update nodes.
//
// A failed allocation does not fail the caller: the service stays without
// VIPs (its svc: destinations resolve to nothing, so it fails closed), the
// failure is logged and counted, and the next policy load tries again.
// Only a failure to read the stored VIPs is returned.
func (s *State) loadServiceVIPs() (bool, error) {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	first := s.services.vips.Load() == nil
	vips := serviceVIPMap{}

	if first {
		stored, err := s.db.ListServices()
		if err != nil {
			return false, fmt.Errorf("reading service addresses: %w", err)
		}

		for i := range stored {
			vips[stored[i].ServiceName()] = stored[i].VIPs()
		}

		// The policy manager starts without VIPs.
		s.services.policySynced = len(vips) == 0
	} else {
		vips = maps.Clone(*s.services.vips.Load())
	}

	created := 0

	for _, name := range s.polMan.ServiceNames() {
		if _, ok := vips[name]; ok {
			continue
		}

		svc, err := s.db.CreateService(s.ipAlloc, name.String())
		if err != nil {
			serviceVIPAllocationFailures.Inc()
			log.Error().
				Err(err).
				Str("service", name.String()).
				Msg("service has no virtual IP addresses; clients cannot reach it until an allocation succeeds")

			continue
		}

		log.Info().
			Str("service", svc.Name).
			Interface("addresses", svc.VIPs()).
			Msg("allocated service virtual IP addresses")

		vips[name] = svc.VIPs()
		created++
	}

	s.services.vips.Store(&vips)

	// The policy manager keeps the VIPs across policy changes; it only
	// needs them again when they changed, or when giving them failed
	// before. Without any service this costs nothing.
	if created == 0 && s.services.policySynced {
		return false, nil
	}

	changed, err := s.polMan.SetServiceVIPs(vips)
	s.services.policySynced = err == nil

	return changed, err
}

// HasServiceVIPs reports whether any service has VIPs.
func (s *State) HasServiceVIPs() bool {
	p := s.services.vips.Load()

	return p != nil && len(*p) > 0
}

// ServiceVIPs returns the VIPs of a service, or nil.
func (s *State) ServiceVIPs(name tailcfg.ServiceName) []netip.Addr {
	p := s.services.vips.Load()
	if p == nil {
		return nil
	}

	return (*p)[name]
}

// deriveServiceHosts returns, for each service with VIPs, the sorted IDs
// of its active hosts: online, unexpired nodes that advertise the service
// and that the policy approves to host it.
func deriveServiceHosts(
	nodes views.Slice[types.NodeView],
	nodeServices func(types.NodeView) []tailcfg.ServiceName,
	vips serviceVIPMap,
) *serviceHostIndex {
	idx := &serviceHostIndex{
		hosts:     serviceHostMap{},
		byNode:    map[types.NodeID][]tailcfg.ServiceName{},
		hostPeers: map[types.NodeID][]types.NodeID{},
		assigned:  map[tailcfg.ServiceName]map[types.NodeID]types.NodeID{},
	}

	if len(vips) == 0 {
		return idx
	}

	for _, node := range nodes.All() {
		if !node.Online() || node.IsExpired() || node.AdvertisedServices().Len() == 0 {
			continue
		}

		approved := nodeServices(node)

		for _, advertised := range node.AdvertisedServices().All() {
			name := tailcfg.ServiceName(advertised)
			if !slices.Contains(approved, name) || len(vips[name]) == 0 {
				continue
			}

			idx.hosts[name] = append(idx.hosts[name], node.ID())
			idx.byNode[node.ID()] = append(idx.byNode[node.ID()], name)
		}
	}

	for name := range idx.hosts {
		slices.Sort(idx.hosts[name])
		idx.hosts[name] = slices.Compact(idx.hosts[name])
	}

	return idx
}

// chooseServiceHost returns the host of a service that viewer sends the
// service's traffic to: among the hosts viewer can see, the one with the
// highest rendezvous score for viewer. Every viewer gets a stable host;
// viewers spread evenly; when a host leaves, only its viewers move.
func chooseServiceHost(viewer types.NodeID, hosts []types.NodeID, visible func(types.NodeID) bool) (types.NodeID, bool) {
	var (
		best      types.NodeID
		bestScore uint64
		found     bool
	)

	for _, h := range hosts {
		if !visible(h) {
			continue
		}

		score := rendezvousScore(viewer, h)
		if !found || score > bestScore || (score == bestScore && h < best) {
			best, bestScore, found = h, score, true
		}
	}

	return best, found
}

// refreshServiceHosts derives the active hosts of each service and the
// host each online viewer uses, see [nextServiceHost]: a viewer keeps its
// host while that host is active, so a joining host takes nobody at once,
// and the viewers of a leaving host move to their rendezvous choice. For
// every viewer whose host changes, it queues a change targeted at that
// viewer with the old and the new host as changed peers: the old host's
// AllowedIPs lose the VIPs, the new host's gain them. Other viewers get
// nothing.
func (s *State) refreshServiceHosts() {
	if s.refreshServiceHostsLocked() {
		s.notifyServiceMoves()
	}
}

// notifyServiceMoves runs the [State.OnServiceHostsMoved] callbacks, which
// hand the queued changes to the batcher.
func (s *State) notifyServiceMoves() {
	s.services.movedMu.Lock()
	fns := slices.Clone(s.services.moved)
	s.services.movedMu.Unlock()

	for _, fn := range fns {
		fn()
	}
}

// followRendezvous reports whether clients follow their rendezvous choice
// at once, which they do during the startup grace: assignments live in
// memory, and without it the first host back after a restart would keep
// every client.
func (s *State) followRendezvous() bool {
	return time.Since(s.services.startedAt) < s.cfg.Services.StartupGrace
}

// sameHostView reports whether a and b have the same active hosts with the
// same peers, so every viewer's host is the same in both.
func sameHostView(a, b *serviceHostIndex) bool {
	if a == nil || len(a.hosts) != len(b.hosts) || len(a.hostPeers) != len(b.hostPeers) {
		return false
	}

	for name, hosts := range b.hosts {
		if !slices.Equal(a.hosts[name], hosts) {
			return false
		}
	}

	for h, peers := range b.hostPeers {
		if !slices.Equal(a.hostPeers[h], peers) {
			return false
		}
	}

	return true
}

// refreshServiceHostsLocked does the work of [State.refreshServiceHosts]
// under the services lock and reports whether it queued changes. When the
// active hosts and their peers are unchanged, no viewer's host can change,
// and it returns without walking the viewers.
func (s *State) refreshServiceHostsLocked() bool {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	vips := s.services.vips.Load()
	if vips == nil {
		return false
	}

	// Which clients are online or may reach a service can change without
	// a host change; let the next rebalance round look again.
	s.services.balanced = nil

	// Read the generation first: a rebuild during this refresh leaves the
	// stored generation behind, so the next reconcile refreshes again.
	gen := s.nodeStore.PeerMapGeneration()

	nodes := s.nodeStore.ListNodes()
	next := deriveServiceHosts(nodes, s.polMan.NodeServices, *vips)
	next.peerGen = gen

	for h := range next.byNode {
		next.hostPeers[h] = s.nodeStore.ListPeerIDs(h)
	}

	prev := s.services.index.Load()
	if sameHostView(prev, next) {
		if prev.peerGen != gen {
			current := *prev
			current.peerGen = gen
			s.services.index.Store(&current)
		}

		return false
	}

	follow := s.followRendezvous()

	var queued []change.Change

	for _, viewer := range nodes.All() {
		if !viewer.Online() {
			s.keepOfflineAssignments(prev, next, viewer.ID())

			continue
		}

		visibleNext := next.visibleTo(viewer.ID())

		var moved []types.NodeID

		for name := range *vips {
			if len(next.hosts[name]) == 0 && (prev == nil || len(prev.hosts[name]) == 0) {
				continue
			}

			if !s.mayReachService(viewer, name) {
				continue
			}

			oldHost, hadOld := prev.hostFor(viewer.ID(), name)
			newHost, hasNew := nextServiceHost(viewer.ID(), oldHost, hadOld, next.hosts[name], visibleNext, follow)

			if hasNew {
				if target, _ := chooseServiceHost(viewer.ID(), next.hosts[name], visibleNext); target != newHost {
					next.assign(name, viewer.ID(), newHost)
				}
			}

			if hadOld == hasNew && oldHost == newHost {
				continue
			}

			if hadOld {
				moved = append(moved, oldHost)
			}

			if hasNew {
				moved = append(moved, newHost)
			}
		}

		if len(moved) == 0 {
			continue
		}

		c := change.PeersChanged("service host moved", moved...)
		c.TargetNode = viewer.ID()
		queued = append(queued, c)
	}

	s.services.index.Store(next)

	if len(queued) == 0 {
		return false
	}

	log.Debug().
		Int("viewers.moved", len(queued)).
		Bool("startup_grace", follow).
		Msg("service hosts changed")

	s.queueServiceMoves(queued)

	return true
}

// keepOfflineAssignments carries an offline viewer's sticky hosts into
// next, so it keeps them when it reconnects, while they stay active.
func (s *State) keepOfflineAssignments(prev, next *serviceHostIndex, viewer types.NodeID) {
	if prev == nil {
		return
	}

	visible := next.visibleTo(viewer)

	for name, viewers := range prev.assigned {
		// Keep it only while the host stays active and visible: once the
		// host leaves, the viewer's next host is its rendezvous choice,
		// also if the old host comes back before the viewer.
		if h, ok := viewers[viewer]; ok && slices.Contains(next.hosts[name], h) && visible(h) {
			next.assign(name, viewer, h)
		}
	}
}

// mayReachService reports whether the policy lets viewer reach any of the
// service's VIPs.
func (s *State) mayReachService(viewer types.NodeView, name tailcfg.ServiceName) bool {
	matchers, err := s.polMan.MatchersForNode(viewer)
	if err != nil {
		return false
	}

	for _, addr := range s.ServiceVIPs(name) {
		if viewer.CanAccessRoute(matchers, netip.PrefixFrom(addr, addr.BitLen())) {
			return true
		}
	}

	return false
}

// reconcileServiceHosts refreshes the service hosts when the peer
// relationships were rebuilt since the last refresh. The map responses
// decide which host a client sees from the index's host peers, so a peer
// change that no refresh followed (a user change, a policy or node write
// that raced) would leave clients without their VIP route. It runs where
// changes are dispatched, so every path that rebuilds peers is covered.
// It returns whether it queued moves; the caller drains them.
func (s *State) reconcileServiceHosts() bool {
	if !s.HasServiceVIPs() {
		return false
	}

	idx := s.services.index.Load()
	if idx != nil && idx.peerGen == s.nodeStore.PeerMapGeneration() {
		return false
	}

	return s.refreshServiceHostsLocked()
}

func (s *State) queueServiceMoves(cs []change.Change) {
	s.services.pendingMu.Lock()
	s.services.pending = append(s.services.pending, cs...)
	s.services.pendingMu.Unlock()
}

// OnServiceHostsMoved registers fn to run after a host change queued
// changes for clients. The queue reaches the batcher only through
// [State.DrainSelfRefreshes], and the caller of the event may send nothing
// itself (for example when no DNS record changed), so fn must dispatch.
func (s *State) OnServiceHostsMoved(fn func()) {
	s.services.movedMu.Lock()
	defer s.services.movedMu.Unlock()

	s.services.moved = append(s.services.moved, fn)
}

// drainServiceMoves returns and clears the queued service-host changes.
func (s *State) drainServiceMoves() []change.Change {
	s.services.pendingMu.Lock()
	defer s.services.pendingMu.Unlock()

	out := s.services.pending
	s.services.pending = nil

	return out
}

// serviceRoutesForPeer returns the VIPs that peer carries in viewer's
// AllowedIPs: those of each service peer hosts, when peer is viewer's
// chosen host of the service and the policy lets viewer reach the service.
func (s *State) serviceRoutesForPeer(
	viewer, peer types.NodeView,
	matchers []matcher.Match,
) []netip.Prefix {
	idx := s.services.index.Load()
	if idx == nil {
		return nil
	}

	hosted := idx.byNode[peer.ID()]
	if len(hosted) == 0 {
		return nil
	}

	var routes []netip.Prefix

	for _, name := range hosted {
		chosen, ok := idx.hostFor(viewer.ID(), name)
		if !ok || chosen != peer.ID() {
			continue
		}

		for _, addr := range s.ServiceVIPs(name) {
			routes = append(routes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	if len(routes) == 0 {
		return nil
	}

	return policy.ReduceRoutes(viewer, routes, matchers)
}

// ServiceHostFor returns the host of a service that viewer's traffic to
// the service's VIPs goes to, if any.
func (s *State) ServiceHostFor(viewer types.NodeID, name tailcfg.ServiceName) (types.NodeID, bool) {
	idx := s.services.index.Load()
	if idx == nil {
		return 0, false
	}

	return idx.hostFor(viewer, name)
}

// ServiceHosts returns the sorted IDs of the active hosts of a service.
func (s *State) ServiceHosts(name tailcfg.ServiceName) []types.NodeID {
	idx := s.services.index.Load()
	if idx == nil {
		return nil
	}

	return slices.Clone(idx.hosts[name])
}

// withServiceRecords adds `<label>.<base domain>` with the VIPs for every
// service that has VIPs. The claim records of hostnameClaims stay as they
// are: those names answer with the addresses of the claiming hosts, so a
// draining host keeps its open connections (a VIP move resets them).
//
// The base-domain name is not published when a node's MagicDNS name uses
// the same label: the node keeps its name, the rule Tailscale applies.
func (s *State) withServiceRecords(records []claimRecord, nodes views.Slice[types.NodeView]) []claimRecord {
	vipsPtr := s.services.vips.Load()
	if vipsPtr == nil || len(*vipsPtr) == 0 || s.cfg.BaseDomain == "" {
		return records
	}

	vips := *vipsPtr

	nodeNames := map[string]bool{}
	for _, n := range nodes.All() {
		nodeNames[strings.ToLower(n.GivenName())] = true
	}

	out := slices.Clone(records)

	for _, svc := range s.polMan.ServiceNames() {
		label := strings.ToLower(svc.WithoutPrefix())
		if len(vips[svc]) == 0 {
			continue
		}

		if nodeNames[label] {
			s.warnServiceNameOnce(svc)

			continue
		}

		for _, addr := range vips[svc] {
			recordType := dnsRecordTypeA
			if addr.Is6() {
				recordType = dnsRecordTypeAAAA
			}

			out = append(out, claimRecord{
				service: svc,
				record: tailcfg.DNSRecord{
					Name:  label + "." + s.cfg.BaseDomain,
					Type:  recordType,
					Value: addr.String(),
				},
			})
		}
	}

	slices.SortStableFunc(out, func(a, b claimRecord) int {
		return cmp.Or(
			strings.Compare(a.record.Name, b.record.Name),
			strings.Compare(a.record.Type, b.record.Type),
			strings.Compare(a.record.Value, b.record.Value),
			cmp.Compare(a.nodeID, b.nodeID),
		)
	})

	return out
}

// warnServiceNameOnce logs once per service that its MagicDNS name is not
// published because a node uses it. Called under claims.mu, which guards
// claims.warned.
func (s *State) warnServiceNameOnce(svc tailcfg.ServiceName) {
	key := svc.String()
	if _, done := s.claims.warned[key]; done {
		return
	}

	if s.claims.warned == nil {
		s.claims.warned = make(map[string]struct{})
	}

	s.claims.warned[key] = struct{}{}

	log.Warn().
		Str("service", key).
		Msg("service name not published: a node uses the same MagicDNS name")
}

// serviceAccessFunc returns a function that reports whether the policy lets
// viewer reach a service, that is, any of its VIPs, see
// [State.mayReachService]. It caches the answer per service.
func (s *State) serviceAccessFunc(viewer types.NodeID) func(tailcfg.ServiceName) bool {
	node, ok := s.nodeStore.GetNode(viewer)
	if !ok {
		return func(tailcfg.ServiceName) bool { return false }
	}

	cache := map[tailcfg.ServiceName]bool{}

	return func(svc tailcfg.ServiceName) bool {
		if v, ok := cache[svc]; ok {
			return v
		}

		v := s.mayReachService(node, svc)
		cache[svc] = v

		return v
	}
}
