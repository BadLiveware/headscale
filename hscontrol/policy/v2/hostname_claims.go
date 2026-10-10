package v2

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
)

var ErrInvalidHostnameClaim = errors.New("invalid hostnameClaims entry")

// hostnameClaimWildcard is the first label of a pattern that lets a node
// claim any name directly below the zone.
const hostnameClaimWildcard = "*"

// HostnameClaims maps a hostname pattern to the tags whose nodes may claim
// it. A node claims a hostname by advertising the service `svc:<label>`
// (the client's AdvertiseServices preference, set with
// `tailscale serve advertise svc:<label>`):
//
//   - "*.<zone>" lets the node claim "<label>.<zone>" for any label;
//   - "<label>.<zone>" lets the node claim exactly that name.
//
// Headscale answers a claimed hostname with the addresses of every online
// node that claims it.
type HostnameClaims map[string][]Tag

// hostnameClaimRule is one validated [HostnameClaims] entry.
type hostnameClaimRule struct {
	// label is the one service label the rule accepts, or
	// [hostnameClaimWildcard] for any label.
	label string
	zone  string
	tags  []Tag
}

// parseHostnameClaimPattern splits a [HostnameClaims] key into its first
// label and its zone, both lowercase and without a trailing dot.
func parseHostnameClaimPattern(pattern string) (string, string, error) {
	name := strings.TrimSuffix(strings.ToLower(pattern), ".")

	label, zone, ok := strings.Cut(name, ".")
	if !ok || zone == "" {
		return "", "", fmt.Errorf(
			"%w: %q must be \"*.<zone>\" or \"<label>.<zone>\"",
			ErrInvalidHostnameClaim, pattern,
		)
	}

	if label != hostnameClaimWildcard {
		err := dnsname.ValidLabel(label)
		if err != nil {
			return "", "", fmt.Errorf("%w: %q: %w", ErrInvalidHostnameClaim, pattern, err)
		}
	}

	err := dnsname.ValidHostname(zone)
	if err != nil {
		return "", "", fmt.Errorf("%w: %q: %w", ErrInvalidHostnameClaim, pattern, err)
	}

	return label, zone, nil
}

// compileHostnameClaims validates the hostnameClaims section and returns its
// rules sorted by pattern, so lookups are deterministic.
func (p *Policy) compileHostnameClaims() ([]hostnameClaimRule, []error) {
	var (
		rules []hostnameClaimRule
		errs  []error
	)

	// Sorted, so the reported errors come in the same order on every load.
	for _, pattern := range slices.Sorted(maps.Keys(p.HostnameClaims)) {
		tags := p.HostnameClaims[pattern]

		label, zone, err := parseHostnameClaimPattern(pattern)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if len(tags) == 0 {
			errs = append(errs, fmt.Errorf("%w: %q lists no tags", ErrInvalidHostnameClaim, pattern))
			continue
		}

		for i := range tags {
			err := p.TagOwners.Contains(&tags[i])
			if err != nil {
				errs = append(errs, err)
			}
		}

		rules = append(rules, hostnameClaimRule{label: label, zone: zone, tags: tags})
	}

	slices.SortFunc(rules, func(a, b hostnameClaimRule) int {
		return strings.Compare(a.label+"."+a.zone, b.label+"."+b.zone)
	})

	return rules, errs
}

// serviceHostnames returns the sorted, unique hostnames that a node with
// nodeTags may claim by advertising services.
func serviceHostnames(rules []hostnameClaimRule, nodeTags []string, services []string) []string {
	var names []string

	for _, rule := range rules {
		if !slices.ContainsFunc(rule.tags, func(t Tag) bool {
			return slices.Contains(nodeTags, string(t))
		}) {
			continue
		}

		for _, svc := range services {
			label := strings.ToLower(tailcfg.AsServiceName(svc).WithoutPrefix())
			if label == "" {
				continue
			}

			if rule.label != hostnameClaimWildcard && rule.label != label {
				continue
			}

			// A long label on a long zone can exceed the DNS name limits.
			name := label + "." + rule.zone
			if dnsname.ValidHostname(name) != nil {
				continue
			}

			names = append(names, name)
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// HasHostnameClaims reports whether the policy has any hostnameClaims rule,
// that is whether a node's advertised services can matter at all.
func (pm *PolicyManager) HasHostnameClaims() bool {
	if pm == nil {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.pol != nil && len(pm.pol.hostnameClaimRules) > 0
}

// ServiceHostnames returns the hostnames node may answer for, given the
// service names it advertises and the policy's hostnameClaims. Only tagged
// nodes can claim hostnames: a claim is an infrastructure role, and tags are
// how a policy names infrastructure.
func (pm *PolicyManager) ServiceHostnames(node types.NodeView, services []string) []string {
	if pm == nil || !node.Valid() || !node.IsTagged() || len(services) == 0 {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.pol == nil {
		return nil
	}

	return serviceHostnames(pm.pol.hostnameClaimRules, node.Tags().AsSlice(), services)
}
