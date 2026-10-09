package hscontrol

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestServicesFetchRetryDelay(t *testing.T) {
	assert.Equal(t, servicesFetchTimeout, retryDelay(0))
	assert.Equal(t, 2*servicesFetchTimeout, retryDelay(1))
	assert.Equal(t, 4*servicesFetchTimeout, retryDelay(2))
	assert.Equal(t, servicesRetryMax, retryDelay(10))
	assert.Equal(t, servicesRetryMax, retryDelay(1000))
}

// A c2n response from a machine that was not asked must be refused
// without consuming the pending fetch, so the real node's answer still
// counts.
func TestServicesFetchWrongMachineKeepsFetch(t *testing.T) {
	app := createTestApp(t)
	f := app.servicesFetcher

	const id = "pending-fetch-id"

	f.mu.Lock()
	f.byID[id] = &servicesFetch{
		nodeID: types.NodeID(4242),
		hash:   "hash",
		timer:  time.AfterFunc(time.Hour, func() {}),
	}
	f.pending[4242] = id
	f.mu.Unlock()

	err := f.complete(id, key.NewMachine().Public(), bufio.NewReader(strings.NewReader("")))
	require.ErrorIs(t, err, errC2NWrongMachine)

	_, stillPending := f.lookup(id)
	assert.True(t, stillPending, "a refused response must not consume the fetch")
}
