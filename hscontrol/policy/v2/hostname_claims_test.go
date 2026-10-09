package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/views"
)

func TestHostnameClaimsValidation(t *testing.T) {
	tests := []struct {
		name    string
		claims  string
		wantErr string
	}{
		{
			name:   "wildcard-zone",
			claims: `{"*.gw.mgmt.example.com": ["tag:gateway"]}`,
		},
		{
			name:   "exact-name",
			claims: `{"grafana.mgmt.example.com": ["tag:gateway"]}`,
		},
		{
			name:   "upper-case-and-trailing-dot",
			claims: `{"*.GW.Example.COM.": ["tag:gateway"]}`,
		},
		{
			name:    "single-label",
			claims:  `{"gateway": ["tag:gateway"]}`,
			wantErr: "must be",
		},
		{
			name:    "wildcard-without-zone",
			claims:  `{"*": ["tag:gateway"]}`,
			wantErr: "must be",
		},
		{
			name:    "wildcard-inside-zone",
			claims:  `{"a.*.example.com": ["tag:gateway"]}`,
			wantErr: "invalid hostnameClaims entry",
		},
		{
			name:    "invalid-label",
			claims:  `{"a_b.example.com": ["tag:gateway"]}`,
			wantErr: "invalid hostnameClaims entry",
		},
		{
			name:    "undefined-tag",
			claims:  `{"*.example.com": ["tag:unknown"]}`,
			wantErr: "tag not found",
		},
		{
			name:    "no-tags",
			claims:  `{"*.example.com": []}`,
			wantErr: "lists no tags",
		},
		{
			name:    "not-a-tag",
			claims:  `{"*.example.com": ["user@"]}`,
			wantErr: "tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := `{
				"tagOwners": {"tag:gateway": ["user@"]},
				"hostnameClaims": ` + tt.claims + `
			}`

			_, err := unmarshalPolicy([]byte(pol))
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestServiceHostnames(t *testing.T) {
	users := types.Users{{ID: 1, Name: "user"}}

	pol := `{
		"tagOwners": {
			"tag:gateway": ["user@"],
			"tag:monitoring": ["user@"],
			"tag:other": ["user@"]
		},
		"hostnameClaims": {
			"*.gw.mgmt.example.com": ["tag:gateway"],
			"grafana.mgmt.example.com": ["tag:monitoring", "tag:gateway"]
		}
	}`

	tagged := func(tags ...string) types.NodeView {
		return (&types.Node{ID: 1, Tags: tags, IPv4: ap("100.64.0.1")}).View()
	}

	untagged := (&types.Node{
		ID:     2,
		UserID: new(users[0].ID),
		User:   &users[0],
		IPv4:   ap("100.64.0.2"),
	}).View()

	pm, err := NewPolicyManager([]byte(pol), users, views.SliceOf([]types.NodeView{}))
	require.NoError(t, err)

	tests := []struct {
		name     string
		node     types.NodeView
		services []string
		want     []string
	}{
		{
			name:     "wildcard-zone-any-label",
			node:     tagged("tag:gateway"),
			services: []string{"svc:gitea", "svc:web"},
			want:     []string{"gitea.gw.mgmt.example.com", "web.gw.mgmt.example.com"},
		},
		{
			name:     "exact-name-and-wildcard",
			node:     tagged("tag:gateway"),
			services: []string{"svc:grafana"},
			want:     []string{"grafana.gw.mgmt.example.com", "grafana.mgmt.example.com"},
		},
		{
			name:     "exact-name-only-for-its-label",
			node:     tagged("tag:monitoring"),
			services: []string{"svc:grafana", "svc:gitea"},
			want:     []string{"grafana.mgmt.example.com"},
		},
		{
			name:     "tag-without-claims",
			node:     tagged("tag:other"),
			services: []string{"svc:gitea"},
			want:     nil,
		},
		{
			name:     "untagged-node-cannot-claim",
			node:     untagged,
			services: []string{"svc:gitea"},
			want:     nil,
		},
		{
			name:     "malformed-service-names-are-ignored",
			node:     tagged("tag:gateway"),
			services: []string{"gitea", "svc:", "svc:a_b", "svc:GITEA"},
			want:     []string{"gitea.gw.mgmt.example.com"},
		},
		{
			name:     "no-services",
			node:     tagged("tag:gateway"),
			services: nil,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pm.ServiceHostnames(tt.node, tt.services))
		})
	}
}

func TestServiceHostnamesFollowPolicyReload(t *testing.T) {
	users := types.Users{{ID: 1, Name: "user"}}
	gw := (&types.Node{ID: 1, Tags: []string{"tag:gateway"}, IPv4: ap("100.64.0.1")}).View()

	pm, err := NewPolicyManager([]byte(`{
		"tagOwners": {"tag:gateway": ["user@"]},
		"hostnameClaims": {"*.gw.example.com": ["tag:gateway"]}
	}`), users, views.SliceOf([]types.NodeView{gw}))
	require.NoError(t, err)

	assert.Equal(t, []string{"gitea.gw.example.com"}, pm.ServiceHostnames(gw, []string{"svc:gitea"}))

	_, err = pm.SetPolicy([]byte(`{"tagOwners": {"tag:gateway": ["user@"]}}`))
	require.NoError(t, err)

	assert.Empty(t, pm.ServiceHostnames(gw, []string{"svc:gitea"}))
}
