package db

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testServicesStableAndDisjoint(t *testing.T, db *HSDatabase) {
	t.Helper()

	prefix4, prefix6 := mpp("100.64.0.0/10"), mpp("fd7a:115c:a1e0::/48")

	alloc, err := NewIPAllocator(db, prefix4, prefix6, types.IPAllocationStrategySequential)
	require.NoError(t, err)

	nodeV4, nodeV6, err := alloc.Next()
	require.NoError(t, err)

	node := types.Node{Hostname: "node", IPv4: nodeV4, IPv6: nodeV6}
	require.NoError(t, db.DB.Save(&node).Error)

	created, err := db.CreateServices(alloc, []string{"svc:cca", "svc:web"})
	require.NoError(t, err)
	require.Len(t, created, 2)

	used := map[netip.Addr]string{*nodeV4: "node", *nodeV6: "node"}

	for _, svc := range created {
		require.Len(t, svc.VIPs(), 2, "%s has one address per family", svc.Name)

		for _, addr := range svc.VIPs() {
			owner, taken := used[addr]
			assert.False(t, taken, "%s got %s, already used by %s", svc.Name, addr, owner)
			used[addr] = svc.Name
		}
	}

	_, err = db.CreateServices(alloc, []string{"svc:cca"})
	require.Error(t, err, "a service name is unique")

	listed, err := db.ListServices()
	require.NoError(t, err)
	require.Len(t, listed, 2)

	for i := range listed {
		assert.Equal(t, created[i].Name, listed[i].Name)
		assert.Equal(t, created[i].VIPs(), listed[i].VIPs(), "the VIPs are stored")
	}

	// A new allocator, as after a restart, must not hand out a VIP.
	restarted, err := NewIPAllocator(db, prefix4, prefix6, types.IPAllocationStrategySequential)
	require.NoError(t, err)

	for range 8 {
		v4, v6, err := restarted.Next()
		require.NoError(t, err)

		for _, addr := range []netip.Addr{*v4, *v6} {
			owner, taken := used[addr]
			assert.False(t, taken, "allocator handed out %s, used by %s", addr, owner)
		}
	}
}

func TestServicesSQLite(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	testServicesStableAndDisjoint(t, db)
}

func TestServicesPostgres(t *testing.T) {
	testServicesStableAndDisjoint(t, newPostgresTestDB(t))
}
