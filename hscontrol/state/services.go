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
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// serviceVIPMap maps a service to its virtual IP addresses (VIPs).
type serviceVIPMap map[tailcfg.ServiceName][]netip.Addr

// serviceHostMap maps a service to the sorted IDs of its active hosts.
type serviceHostMap map[tailcfg.ServiceName][]types.NodeID

// serviceHostIndex is the set of active service hosts, indexed both ways,
// and the host each client is assigned to. It is immutable once stored.
type serviceHostIndex struct {
	hosts  serviceHostMap
	byNode map[types.NodeID][]tailcfg.ServiceName

	// assigned is the host each viewer uses per service. A viewer keeps it
	// while that host is active and visible, see [serviceHostIndex.hostFor].
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
}

// loadServiceVIPs reads the stored VIPs, allocates VIPs for the services
// the policy defines that have none yet, and gives the result to the policy
// manager. It reports whether the policy manager needs to update nodes.
func (s *State) loadServiceVIPs() (bool, error) {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	vips := serviceVIPMap{}
	if p := s.services.vips.Load(); p != nil {
		vips = maps.Clone(*p)
	} else {
		stored, err := s.db.ListServices()
		if err != nil {
			return false, err
		}

		for i := range stored {
			vips[stored[i].ServiceName()] = stored[i].VIPs()
		}
	}

	var missing []string

	for _, name := range s.polMan.ServiceNames() {
		if _, ok := vips[name]; !ok {
			missing = append(missing, name.String())
		}
	}

	created, err := s.db.CreateServices(s.ipAlloc, missing)
	if err != nil {
		return false, fmt.Errorf("allocating service addresses: %w", err)
	}

	for i := range created {
		log.Info().
			Str("service", created[i].Name).
			Interface("addresses", created[i].VIPs()).
			Msg("allocated service virtual IP addresses")

		vips[created[i].ServiceName()] = created[i].VIPs()
	}

	s.services.vips.Store(&vips)

	return s.polMan.SetServiceVIPs(vips)
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
		hosts:    serviceHostMap{},
		byNode:   map[types.NodeID][]tailcfg.ServiceName{},
		assigned: map[tailcfg.ServiceName]map[types.NodeID]types.NodeID{},
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
// service's traffic to: among the hosts viewer can see (peers, sorted), the
// one with the highest rendezvous score for viewer. Every viewer gets a
// stable host; viewers spread evenly; when a host leaves, only its viewers
// move.
func chooseServiceHost(viewer types.NodeID, hosts, peers []types.NodeID) (types.NodeID, bool) {
	var (
		best      types.NodeID
		bestScore uint64
		found     bool
	)

	for _, h := range hosts {
		if _, ok := slices.BinarySearch(peers, h); !ok {
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

// refreshServiceHostsLocked does the work of [State.refreshServiceHosts]
// under the services lock and reports whether it queued changes.
func (s *State) refreshServiceHostsLocked() bool {
	vips := s.services.vips.Load()
	if vips == nil {
		return false
	}

	s.services.mu.Lock()
	defer s.services.mu.Unlock()

	nodes := s.nodeStore.ListNodes()
	next := deriveServiceHosts(nodes, s.polMan.NodeServices, *vips)
	prev := s.services.index.Load()
	follow := s.followRendezvous()

	names := slices.Sorted(maps.Keys(*vips))

	for _, name := range names {
		next.assigned[name] = map[types.NodeID]types.NodeID{}
	}

	// Without any host before or now there is nothing to assign or move;
	// skip the walk over every online viewer.
	if len(next.byNode) == 0 && (prev == nil || len(prev.byNode) == 0) {
		s.services.index.Store(next)

		return false
	}

	if prev != nil {
		for _, viewer := range nodes.All() {
			for _, name := range names {
				if h, ok := prev.assigned[name][viewer.ID()]; ok && !viewer.Online() {
					next.assigned[name][viewer.ID()] = h
				}
			}
		}
	}

	var queued []change.Change

	for _, viewer := range nodes.All() {
		if !viewer.Online() {
			continue
		}

		peers := s.nodeStore.ListPeerIDs(viewer.ID())

		var moved []types.NodeID

		for _, name := range names {
			oldHost, hadOld := prev.hostFor(viewer.ID(), name, peers)
			newHost, hasNew := nextServiceHost(viewer.ID(), oldHost, hadOld, next.hosts[name], peers, follow)

			if hasNew {
				next.assigned[name][viewer.ID()] = newHost
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

	peers := s.nodeStore.ListPeerIDs(viewer.ID())

	var routes []netip.Prefix

	for _, name := range hosted {
		chosen, ok := idx.hostFor(viewer.ID(), name, peers)
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

	return idx.hostFor(viewer, name, s.nodeStore.ListPeerIDs(viewer))
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
			log.Warn().
				Str("service", svc.String()).
				Msg("service name not published: a node uses the same MagicDNS name")

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

// serviceAccessFunc returns a function that reports whether the policy lets
// viewer reach a service, that is, any of its VIPs.
func (s *State) serviceAccessFunc(viewer types.NodeID) func(tailcfg.ServiceName) bool {
	node, ok := s.nodeStore.GetNode(viewer)
	if !ok {
		return func(tailcfg.ServiceName) bool { return false }
	}

	matchers, err := s.polMan.MatchersForNode(node)
	if err != nil {
		return func(tailcfg.ServiceName) bool { return false }
	}

	cache := map[tailcfg.ServiceName]bool{}

	return func(svc tailcfg.ServiceName) bool {
		if v, ok := cache[svc]; ok {
			return v
		}

		var prefixes []netip.Prefix
		for _, addr := range s.ServiceVIPs(svc) {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}

		v := len(policy.ReduceRoutes(node, prefixes, matchers)) > 0
		cache[svc] = v

		return v
	}
}
