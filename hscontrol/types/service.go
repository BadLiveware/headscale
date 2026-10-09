package types

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
)

// Service is a Tailscale Service (`svc:<label>`) that has virtual IP
// addresses (VIPs). Nodes that host the service receive traffic for the
// VIPs. A row is created the first time a policy approves hosts for the
// service, and it is kept when the policy drops the service, so the
// service keeps its addresses and they are never given to another service
// or node.
type Service struct {
	ID uint64 `gorm:"primary_key"`

	// Name is the service name, `svc:<label>`.
	Name string `gorm:"uniqueIndex"`

	// IPv4 and IPv6 are the VIPs. A family is nil when the tailnet has no
	// prefix of that family.
	IPv4 *netip.Addr `gorm:"column:ipv4;serializer:text"`
	IPv6 *netip.Addr `gorm:"column:ipv6;serializer:text"`

	CreatedAt time.Time
}

// ServiceName returns the service name in Tailscale form.
func (s *Service) ServiceName() tailcfg.ServiceName {
	return tailcfg.ServiceName(s.Name)
}

// VIPs returns the service's addresses, IPv4 first.
func (s *Service) VIPs() []netip.Addr {
	var addrs []netip.Addr

	if s.IPv4 != nil {
		addrs = append(addrs, *s.IPv4)
	}

	if s.IPv6 != nil {
		addrs = append(addrs, *s.IPv6)
	}

	return addrs
}
