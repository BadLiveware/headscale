package state

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

const (
	dnsRecordTypeA    = "A"
	dnsRecordTypeAAAA = "AAAA"
)

// claimRecord is one DNS record that a node publishes by claiming a
// hostname. nodeID is kept so each viewer only gets the records of nodes
// it can see.
type claimRecord struct {
	nodeID types.NodeID
	record tailcfg.DNSRecord
}

// hostnameClaims caches the records derived from node claims, so a map
// response reads them instead of scanning every node.
type hostnameClaims struct {
	// mu serialises refreshes, so a slow derivation from an older
	// snapshot cannot overwrite the result of a newer one.
	mu      sync.Mutex
	records atomic.Pointer[[]claimRecord]

	// inUse is set once any record has been published and stays set. A
	// node can then hold claim records, so every response that can change
	// what it may see carries the DNS config, see
	// [State.HostnameClaimsInUse].
	inUse atomic.Bool

	// warned holds the names that shadowed the MagicDNS base domain at the
	// last refresh, so each is logged once while it does. Guarded by mu.
	warned map[string]struct{}
}

// hostnamesFunc returns the hostnames a node may claim with the given
// advertised services; [policy.PolicyManager.ServiceHostnames] in production.
type hostnamesFunc func(node types.NodeView, services []string) []string

// deriveClaimRecords returns an A or AAAA record for each address of each
// online node, for each hostname it advertises and the policy lets it claim.
// The records are sorted. A name directly below baseDomain is dropped and
// returned in shadowed: that zone holds the MagicDNS names of nodes, and a
// claim must not shadow one.
func deriveClaimRecords(
	nodes views.Slice[types.NodeView],
	hostnames hostnamesFunc,
	baseDomain string,
) ([]claimRecord, []string) {
	var (
		records  []claimRecord
		shadowed []string
	)

	for _, node := range nodes.All() {
		// Online is cached and only rewritten when expiry is processed; a
		// key that has just expired must not claim in the meantime.
		if !node.Online() || node.IsExpired() || node.AdvertisedServices().Len() == 0 {
			continue
		}

		for _, name := range hostnames(node, node.AdvertisedServices().AsSlice()) {
			_, zone, _ := strings.Cut(name, ".")
			if baseDomain != "" && strings.EqualFold(zone, baseDomain) {
				shadowed = append(shadowed, name)
				continue
			}

			for _, ip := range node.IPs() {
				recordType := dnsRecordTypeA
				if ip.Is6() {
					recordType = dnsRecordTypeAAAA
				}

				records = append(records, claimRecord{
					nodeID: node.ID(),
					record: tailcfg.DNSRecord{
						Name:  name,
						Type:  recordType,
						Value: ip.String(),
					},
				})
			}
		}
	}

	slices.SortFunc(records, func(a, b claimRecord) int {
		return cmp.Or(
			strings.Compare(a.record.Name, b.record.Name),
			strings.Compare(a.record.Type, b.record.Type),
			strings.Compare(a.record.Value, b.record.Value),
			cmp.Compare(a.nodeID, b.nodeID),
		)
	})

	return records, shadowed
}

// refreshHostnameClaims derives the claimed-hostname records from the
// current nodes and policy. It returns a DNS change when they differ from
// the previous result, and an empty change otherwise.
//
// Call it after every event that can change a claim: a node coming online
// or going offline, a node's advertised services, tags or addresses, a
// node's deletion, and a policy change.
func (s *State) refreshHostnameClaims() change.Change {
	// Without a rule nothing can be claimed, and without published records
	// nothing must be withdrawn: skip the scan of every node, which would
	// otherwise run on every connect and disconnect.
	if !s.polMan.HasHostnameClaims() && !s.claims.inUse.Load() {
		return change.Change{}
	}

	s.claims.mu.Lock()
	defer s.claims.mu.Unlock()

	next, shadowed := deriveClaimRecords(s.nodeStore.ListNodes(), s.polMan.ServiceHostnames, s.cfg.BaseDomain)

	// Warn once per shadowing name while it shadows; forget names that no
	// longer do, so the set stays as small as the current claims.
	warned := make(map[string]struct{}, len(shadowed))
	for _, name := range shadowed {
		warned[name] = struct{}{}

		if _, done := s.claims.warned[name]; done {
			continue
		}

		log.Warn().
			Str("hostname", name).
			Str("base_domain", s.cfg.BaseDomain).
			Msg("ignoring claimed hostname directly below the MagicDNS base domain; use a zone outside it or a subzone")
	}

	s.claims.warned = warned

	if len(next) > 0 {
		s.claims.inUse.Store(true)
	}

	var prev []claimRecord
	if p := s.claims.records.Load(); p != nil {
		prev = *p
	}

	s.claims.records.Store(&next)

	if slices.Equal(prev, next) {
		return change.Change{}
	}

	log.Debug().Int("records", len(next)).Msg("hostname claims changed")

	return change.HostnameClaims()
}

// withHostnameClaims refreshes the claimed-hostname records and appends the
// resulting change to cs when they changed.
func (s *State) withHostnameClaims(cs []change.Change) []change.Change {
	c := s.refreshHostnameClaims()
	if c.IsEmpty() {
		return cs
	}

	return append(cs, c)
}

// HostnameClaimsInUse reports whether claim records have been published
// since Headscale started. It stays true after the last claim is gone: a
// client may still hold records, and a policy, tag or expiry change that
// removes them must still send the DNS config. Sending it is cheap, because
// a connection drops a DNS config equal to the one its client holds.
func (s *State) HostnameClaimsInUse() bool {
	return s.claims.inUse.Load()
}

// HostnameClaimRecords returns the claimed-hostname records that viewer may
// see: those of viewer itself and of the nodes the policy makes its peers.
// A viewer that cannot reach a node does not learn its name or addresses.
//
// The order matters: the Tailscale client answers a name with only the
// first address of each family it holds for that name. The records are
// therefore ordered per viewer, see [orderClaimRecordsForViewer], so that
// viewers spread over the claiming nodes.
func (s *State) HostnameClaimRecords(viewer types.NodeID) []tailcfg.DNSRecord {
	all := s.claims.records.Load()
	if all == nil || len(*all) == 0 {
		return nil
	}

	peers := s.nodeStore.ListPeerIDs(viewer)

	var visible []claimRecord

	for _, r := range *all {
		_, isPeer := slices.BinarySearch(peers, r.nodeID)
		if r.nodeID != viewer && !isPeer {
			continue
		}

		visible = append(visible, r)
	}

	orderClaimRecordsForViewer(visible, viewer)

	records := make([]tailcfg.DNSRecord, len(visible))
	for i, r := range visible {
		records[i] = r.record
	}

	return records
}

// orderClaimRecordsForViewer sorts records by name and, within a name, puts
// the records of the node with the highest rendezvous score for viewer
// first. Rendezvous (highest random weight) hashing gives each viewer a
// stable choice of node per name, spreads viewers evenly over the nodes,
// and when a node leaves, only the viewers that chose it move.
func orderClaimRecordsForViewer(records []claimRecord, viewer types.NodeID) {
	slices.SortStableFunc(records, func(a, b claimRecord) int {
		return cmp.Or(
			strings.Compare(a.record.Name, b.record.Name),
			cmp.Compare(rendezvousScore(viewer, b.nodeID), rendezvousScore(viewer, a.nodeID)),
			cmp.Compare(a.nodeID, b.nodeID),
			strings.Compare(a.record.Type, b.record.Type),
		)
	})
}

// rendezvousScore is a deterministic pseudo-random weight for the pair,
// the SplitMix64 finaliser over both IDs. It is stable across restarts, so
// a viewer keeps its choice of node.
func rendezvousScore(viewer, node types.NodeID) uint64 {
	const (
		golden = 0x9e3779b97f4a7c15
		mix1   = 0xbf58476d1ce4e5b9
		mix2   = 0x94d049bb133111eb
	)

	z := uint64(viewer)*golden + uint64(node)
	z = (z ^ (z >> 30)) * mix1
	z = (z ^ (z >> 27)) * mix2

	return z ^ (z >> 31)
}

// ErrServicesHashMoved is returned by [State.SetNodeAdvertisedServices] when
// the node reported a different services hash after the list was requested.
var ErrServicesHashMoved = errors.New("node reported a newer services hash")

// SetNodeAdvertisedServices stores the services a node reports as active
// together with the [tailcfg.Hostinfo.ServicesHash] they belong to, and
// returns the DNS change when this alters the claimed hostnames.
//
// It stores them only while hash is still the hash in the node's Hostinfo,
// checked in the same NodeStore write: a list fetched for an older hash is
// stale and is never applied, so a withdrawn service cannot come back from a
// late answer. It then returns [ErrServicesHashMoved].
func (s *State) SetNodeAdvertisedServices(
	id types.NodeID,
	hash string,
	services []string,
) (change.Change, error) {
	var moved bool

	_, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		var current string
		if n.Hostinfo != nil {
			current = n.Hostinfo.ServicesHash
		}

		if current != hash {
			moved = true

			return
		}

		n.AdvertisedServices = services
		n.AdvertisedServicesHash = hash
	})
	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotFound, id)
	}

	if moved {
		return change.Change{}, ErrServicesHashMoved
	}

	return s.refreshHostnameClaims(), nil
}

// WithdrawStaleAdvertisedServices drops a node's stored services when they
// belong to an older hash than the one in its Hostinfo, and returns the DNS
// change. Call it when the list for the new hash cannot be fetched: the node
// changed its services, maybe withdrawing one, so the old list must not keep
// claiming. The stored hash stays, so the list is still fetched again.
func (s *State) WithdrawStaleAdvertisedServices(id types.NodeID) (change.Change, error) {
	_, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		var current string
		if n.Hostinfo != nil {
			current = n.Hostinfo.ServicesHash
		}

		if current != n.AdvertisedServicesHash {
			n.AdvertisedServices = nil
		}
	})
	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotFound, id)
	}

	return s.refreshHostnameClaims(), nil
}

// HostnameClaimsConfigured reports whether the policy has any hostnameClaims
// rule. Without one, the services a node advertises cannot matter.
func (s *State) HostnameClaimsConfigured() bool {
	return s.polMan.HasHostnameClaims()
}

// OnPolicyReload registers fn to run after every policy reload, once the
// new policy is in effect.
func (s *State) OnPolicyReload(fn func()) {
	s.policyReloadedMu.Lock()
	defer s.policyReloadedMu.Unlock()

	s.policyReloaded = append(s.policyReloaded, fn)
}

func (s *State) runPolicyReloaded() {
	s.policyReloadedMu.Lock()
	fns := slices.Clone(s.policyReloaded)
	s.policyReloadedMu.Unlock()

	for _, fn := range fns {
		fn()
	}
}
