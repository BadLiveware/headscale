package state

import (
	"cmp"
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
}

// hostnamesFunc returns the hostnames a node may claim with the given
// advertised services; [policy.PolicyManager.ServiceHostnames] in production.
type hostnamesFunc func(node types.NodeView, services []string) []string

// deriveClaimRecords returns an A or AAAA record for each address of each
// online node, for each hostname it advertises and the policy lets it claim.
// The result is sorted. A name directly below baseDomain is dropped: that
// zone holds the MagicDNS names of nodes, and a claim must not shadow one.
func deriveClaimRecords(
	nodes views.Slice[types.NodeView],
	hostnames hostnamesFunc,
	baseDomain string,
) []claimRecord {
	var records []claimRecord

	for _, node := range nodes.All() {
		if !node.Online() || node.AdvertisedServices().Len() == 0 {
			continue
		}

		for _, name := range hostnames(node, node.AdvertisedServices().AsSlice()) {
			_, zone, _ := strings.Cut(name, ".")
			if baseDomain != "" && strings.EqualFold(zone, baseDomain) {
				log.Debug().
					Str("hostname", name).
					EmbedObject(node).
					Msg("ignoring hostname claim in the MagicDNS base domain")

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

	return records
}

// refreshHostnameClaims derives the claimed-hostname records from the
// current nodes and policy. It returns a DNS change when they differ from
// the previous result, and an empty change otherwise.
//
// Call it after every event that can change a claim: a node coming online
// or going offline, a node's advertised services, tags or addresses, a
// node's deletion, and a policy change.
func (s *State) refreshHostnameClaims() change.Change {
	s.claims.mu.Lock()
	defer s.claims.mu.Unlock()

	next := deriveClaimRecords(s.nodeStore.ListNodes(), s.polMan.ServiceHostnames, s.cfg.BaseDomain)

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

// HasHostnameClaims reports whether any node currently publishes a claimed
// hostname.
func (s *State) HasHostnameClaims() bool {
	records := s.claims.records.Load()

	return records != nil && len(*records) > 0
}

// HostnameClaimRecords returns the claimed-hostname records that viewer may
// see: those of viewer itself and of the nodes the policy makes its peers.
// A viewer that cannot reach a node does not learn its name or addresses.
func (s *State) HostnameClaimRecords(viewer types.NodeID) []tailcfg.DNSRecord {
	all := s.claims.records.Load()
	if all == nil || len(*all) == 0 {
		return nil
	}

	peers := s.nodeStore.ListPeerIDs(viewer)

	var records []tailcfg.DNSRecord

	for _, r := range *all {
		_, isPeer := slices.BinarySearch(peers, r.nodeID)
		if r.nodeID != viewer && !isPeer {
			continue
		}

		records = append(records, r.record)
	}

	return records
}

// SetNodeAdvertisedServices stores the services a node reports as active
// together with the [tailcfg.Hostinfo.ServicesHash] they belong to, and
// returns the DNS change when this alters the claimed hostnames.
func (s *State) SetNodeAdvertisedServices(
	id types.NodeID,
	hash string,
	services []string,
) (change.Change, error) {
	_, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.AdvertisedServices = services
		n.AdvertisedServicesHash = hash
	})
	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotFound, id)
	}

	return s.refreshHostnameClaims(), nil
}
