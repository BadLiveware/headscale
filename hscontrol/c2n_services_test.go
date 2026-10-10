package hscontrol

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestServicesFetchRetryDelay(t *testing.T) {
	assert.Equal(t, servicesFetchTimeout, retryDelay(0))
	assert.Equal(t, 2*servicesFetchTimeout, retryDelay(1))
	assert.Equal(t, 4*servicesFetchTimeout, retryDelay(2))
	assert.Equal(t, servicesRetryMax, retryDelay(10))
	assert.Equal(t, servicesRetryMax, retryDelay(1000))
}

// fetchedHash is the services hash every fixture's pending fetch was made
// for.
const fetchedHash = "h1"

// c2nFixture is an app with one node in the NodeStore that reports
// services hash hostinfoHash, and a pending fetch for fetchedHash.
type c2nFixture struct {
	app    *Headscale
	f      *servicesFetcher
	node   types.NodeView
	nodeID types.NodeID
	id     string
}

func newC2NFixture(t *testing.T, hostinfoHash string) *c2nFixture {
	t.Helper()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("c2n-user")
	n := app.state.CreateRegisteredNodeForTest(user, "c2n-node")
	n.Hostinfo = &tailcfg.Hostinfo{ServicesHash: hostinfoHash}
	n.Tags = []string{"tag:gateway"}
	node := app.state.PutNodeInStoreForTest(*n)

	fx := &c2nFixture{app: app, f: app.servicesFetcher, node: node, nodeID: node.ID(), id: "pending-fetch-id"}

	fx.f.mu.Lock()
	fx.f.byID[fx.id] = &servicesFetch{
		nodeID: fx.nodeID,
		hash:   fetchedHash,
		timer:  time.AfterFunc(time.Hour, func() {}),
	}
	fx.f.pending[fx.nodeID] = fx.id
	fx.f.mu.Unlock()

	t.Cleanup(fx.f.stop)

	return fx
}

// vipServicesBody is a node's serialised HTTP answer to GET /vip-services
// for fetchedHash.
func vipServicesBody(services ...string) *bufio.Reader {
	parts := make([]string, 0, len(services))
	for _, s := range services {
		parts = append(parts, fmt.Sprintf(`{"Name":%q,"Active":true}`, s))
	}

	body := fmt.Sprintf(`{"VIPServices":[%s],"ServicesHash":%q}`, strings.Join(parts, ","), fetchedHash)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)

	return bufio.NewReader(strings.NewReader(resp))
}

// pending reports whether the fixture's fetch is still pending.
func (fx *c2nFixture) pending() bool {
	fx.f.mu.Lock()
	defer fx.f.mu.Unlock()

	_, ok := fx.f.byID[fx.id]

	return ok
}

func (fx *c2nFixture) stored(t *testing.T) (string, []string) {
	t.Helper()

	node, ok := fx.app.state.GetNodeByID(fx.nodeID)
	require.True(t, ok)

	return node.AdvertisedServicesHash(), node.AdvertisedServices().AsSlice()
}

// A c2n response from a machine that was not asked must be refused
// without consuming the pending fetch, so the real node's answer still
// counts.
func TestServicesFetchWrongMachineKeepsFetch(t *testing.T) {
	fx := newC2NFixture(t, fetchedHash)

	err := fx.f.complete(fx.id, key.NewMachine().Public(), vipServicesBody("svc:grafana"))
	require.ErrorIs(t, err, errC2NWrongMachine)

	stillPending := fx.pending()
	assert.True(t, stillPending, "a refused response must not consume the fetch")

	hash, services := fx.stored(t)
	assert.Empty(t, hash)
	assert.Empty(t, services)

	// The node's own answer is then applied.
	err = fx.f.complete(fx.id, fx.node.MachineKey(), vipServicesBody("svc:grafana"))
	require.NoError(t, err)

	hash, services = fx.stored(t)
	assert.Equal(t, fetchedHash, hash)
	assert.Equal(t, []string{"svc:grafana"}, services)
}

// An answer for a hash the node has moved past is stale and must not be
// stored: it can contain a service the node has withdrawn since.
func TestServicesFetchDropsAnswerForOlderHash(t *testing.T) {
	fx := newC2NFixture(t, "h2")

	err := fx.f.complete(fx.id, fx.node.MachineKey(), vipServicesBody("svc:grafana"))
	require.NoError(t, err)

	hash, services := fx.stored(t)
	assert.Empty(t, hash)
	assert.Empty(t, services)
}

// A bad answer consumes the fetch, so it must schedule a retry like an
// unanswered fetch, instead of leaving the node without one.
func TestServicesFetchBadAnswerSchedulesRetry(t *testing.T) {
	fx := newC2NFixture(t, fetchedHash)

	bad := bufio.NewReader(strings.NewReader("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"))

	err := fx.f.complete(fx.id, fx.node.MachineKey(), bad)
	require.ErrorIs(t, err, errC2NStatus)

	fx.f.mu.Lock()
	b, ok := fx.f.backoff[fx.nodeID]
	fx.f.mu.Unlock()

	require.True(t, ok, "a failed answer must schedule a retry")
	assert.Equal(t, fetchedHash, b.hash)
	assert.Equal(t, 1, b.failures)
	assert.NotNil(t, b.retry)
}

// When the node stops advertising services, a fetch still in flight must
// be cancelled, so its answer cannot bring the services back.
func TestServicesFetchDrainCancelsPendingFetch(t *testing.T) {
	fx := newC2NFixture(t, "")

	fx.f.sync(fx.nodeID)

	stillPending := fx.pending()
	assert.False(t, stillPending, "draining must cancel the pending fetch")

	err := fx.f.complete(fx.id, fx.node.MachineKey(), vipServicesBody("svc:grafana"))
	require.ErrorIs(t, err, errUnknownC2NRequest)

	_, services := fx.stored(t)
	assert.Empty(t, services)
}
