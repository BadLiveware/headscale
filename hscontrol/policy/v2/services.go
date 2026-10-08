package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
)

var (
	ErrServiceNotDefined  = errors.New("service not defined in autoApprovers.services")
	ErrServiceInvalidName = errors.New("invalid service name")
	ErrServiceNoHosts     = errors.New("autoApprovers.services entry lists no tags")
	ErrServiceOnlyDst     = errors.New("a service can only be a destination")
)

// servicePrefix starts every service name, `svc:<label>`.
const servicePrefix = "svc:"

func isService(str string) bool {
	return strings.HasPrefix(str, servicePrefix)
}

// Service is a policy alias for a Tailscale Service, `svc:<label>`. It
// resolves to the service's virtual IP addresses (VIPs), so a grant or ACL
// with a service destination lets its sources reach the service through
// the VIPs. A service is defined by its key in autoApprovers.services.
type Service string

func (s *Service) Validate() error {
	err := tailcfg.ServiceName(*s).Validate()
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrServiceInvalidName, string(*s), err)
	}

	return nil
}

func (s *Service) UnmarshalJSON(b []byte) error {
	*s = Service(strings.Trim(string(b), `"`))

	return s.Validate()
}

// MarshalJSON marshals the Service to JSON.
func (s *Service) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*s))
}

func (s *Service) String() string {
	return string(*s)
}

func (s *Service) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(s.resolve(p, users, nodes))
}

// resolve returns the service's VIPs. A defined service without VIPs yet
// (the server has not allocated them) resolves to an empty set.
func (s *Service) resolve(p *Policy, _ types.Users, _ views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, addr := range p.serviceVIPs[tailcfg.ServiceName(*s)] {
		ips.Add(addr)
	}

	return ips.IPSet()
}

// ServiceApprovers maps a service name to the tags whose nodes may host
// the service. It is the `services` part of autoApprovers, in Tailscale's
// grammar: `"svc:cca": ["tag:gw-cca"]`.
type ServiceApprovers map[tailcfg.ServiceName][]Tag

// validateServices checks the autoApprovers.services section and every
// service alias in ACLs and grants.
func (p *Policy) validateServices() []error {
	var errs []error

	for name, tags := range p.AutoApprovers.Services {
		err := name.Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %q: %w", ErrServiceInvalidName, string(name), err))
		}

		if len(tags) == 0 {
			errs = append(errs, fmt.Errorf("%w: %q", ErrServiceNoHosts, string(name)))
		}

		for i := range tags {
			err := p.TagOwners.Contains(&tags[i])
			if err != nil {
				errs = append(errs, fmt.Errorf("autoApprovers.services %q: %w", string(name), err))
			}
		}
	}

	defined := func(s *Service) error {
		if _, ok := p.AutoApprovers.Services[tailcfg.ServiceName(*s)]; ok {
			return nil
		}

		return fmt.Errorf("%w: %q", ErrServiceNotDefined, string(*s))
	}

	for _, acl := range p.ACLs {
		for _, src := range acl.Sources {
			if s, ok := src.(*Service); ok {
				errs = append(errs, fmt.Errorf("%w: src %q", ErrServiceOnlyDst, string(*s)))
			}
		}

		for _, dst := range acl.Destinations {
			if s, ok := dst.Alias.(*Service); ok {
				if err := defined(s); err != nil { //nolint:noinlineerr
					errs = append(errs, err)
				}
			}
		}
	}

	for _, grant := range p.Grants {
		for _, src := range grant.Sources {
			if s, ok := src.(*Service); ok {
				errs = append(errs, fmt.Errorf("%w: src %q", ErrServiceOnlyDst, string(*s)))
			}
		}

		for _, dst := range grant.Destinations {
			if s, ok := dst.(*Service); ok {
				if err := defined(s); err != nil { //nolint:noinlineerr
					errs = append(errs, err)
				}

				if grant.HasVia() {
					errs = append(errs, fmt.Errorf("%w: %q with via", ErrServiceOnlyDst, string(*s)))
				}
			}
		}
	}

	for _, ssh := range p.SSHs {
		for _, src := range ssh.Sources {
			if s, ok := src.(*Service); ok {
				errs = append(errs, fmt.Errorf("%w: ssh src %q", ErrServiceOnlyDst, string(*s)))
			}
		}

		for _, dst := range ssh.Destinations {
			if s, ok := dst.(*Service); ok {
				errs = append(errs, fmt.Errorf("%w: ssh dst %q is not supported", ErrServiceOnlyDst, string(*s)))
			}
		}
	}

	for _, na := range p.NodeAttrs {
		for _, target := range na.Targets {
			if s, ok := target.(*Service); ok {
				errs = append(errs, fmt.Errorf("%w: nodeAttrs target %q", ErrServiceOnlyDst, string(*s)))
			}
		}
	}

	return errs
}

// serviceNames returns the services the policy defines, sorted.
func (p *Policy) serviceNames() []tailcfg.ServiceName {
	if p == nil {
		return nil
	}

	names := make([]tailcfg.ServiceName, 0, len(p.AutoApprovers.Services))
	for name := range p.AutoApprovers.Services {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// approvedServices returns the sorted services that a node with nodeTags
// may host. Only tagged nodes host services.
func (p *Policy) approvedServices(nodeTags []string) []tailcfg.ServiceName {
	if p == nil || len(nodeTags) == 0 {
		return nil
	}

	var names []tailcfg.ServiceName

	for name, tags := range p.AutoApprovers.Services {
		if slices.ContainsFunc(tags, func(t Tag) bool {
			return slices.Contains(nodeTags, string(t))
		}) {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

// nodeServiceVIPs returns the VIPs of every service the node may host,
// as single-address prefixes. A host treats them as its own addresses:
// filter rules for them reach it, and they make it a peer of the nodes
// that may reach the service.
func (p *Policy) nodeServiceVIPs(node types.NodeView) []netip.Prefix {
	if p == nil || len(p.serviceVIPs) == 0 || !node.IsTagged() {
		return nil
	}

	var prefixes []netip.Prefix

	for _, name := range p.approvedServices(node.Tags().AsSlice()) {
		for _, addr := range p.serviceVIPs[name] {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	return prefixes
}

// addServiceHostCaps stamps the `service-host` capability on every node
// that may host a service with VIPs. Its value is one
// [tailcfg.ServiceIPMappings] object: the client accepts exactly one.
func (p *Policy) addServiceHostCaps(
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
	nodes views.Slice[types.NodeView],
) error {
	if p == nil || len(p.serviceVIPs) == 0 {
		return nil
	}

	for _, node := range nodes.All() {
		if !node.IsTagged() {
			continue
		}

		mappings := tailcfg.ServiceIPMappings{}

		for _, name := range p.approvedServices(node.Tags().AsSlice()) {
			if addrs := p.serviceVIPs[name]; len(addrs) > 0 {
				mappings[name] = addrs
			}
		}

		if len(mappings) == 0 {
			continue
		}

		raw, err := json.Marshal(mappings)
		if err != nil {
			return fmt.Errorf("encoding service-host capability: %w", err)
		}

		capMap, ok := capMaps[node.ID()]
		if !ok {
			capMap = tailcfg.NodeCapMap{}
			capMaps[node.ID()] = capMap
		}

		capMap[nodecap.ServiceHost] = []tailcfg.RawMessage{tailcfg.RawMessage(raw)}
	}

	return nil
}

// ServiceNames returns the services the policy defines in
// autoApprovers.services, sorted. The server allocates VIPs for them.
func (pm *PolicyManager) ServiceNames() []tailcfg.ServiceName {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.pol.serviceNames()
}

// SetServiceVIPs sets the virtual IP addresses of the services and
// recompiles the policy: service destinations resolve to them, hosts get
// the `service-host` capability, and hosts become peers of the nodes that
// may reach their services. It reports whether nodes need an update.
func (pm *PolicyManager) SetServiceVIPs(vips map[tailcfg.ServiceName][]netip.Addr) (bool, error) {
	if pm == nil {
		return false, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	prev := pm.serviceVIPs
	pm.serviceVIPs = vips

	changed, err := pm.updateLocked()
	if err != nil {
		pm.serviceVIPs = prev

		if pm.pol != nil {
			pm.pol.serviceVIPs = prev
		}

		return false, err
	}

	return changed, nil
}

// NodeServices returns the sorted services that node may host: the node is
// tagged and one of its tags is listed for the service in
// autoApprovers.services.
func (pm *PolicyManager) NodeServices(node types.NodeView) []tailcfg.ServiceName {
	if pm == nil || !node.Valid() || !node.IsTagged() {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.pol.approvedServices(node.Tags().AsSlice())
}
