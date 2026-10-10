package hscontrol

import (
	"bytes"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// lockedBuffer is a [bytes.Buffer] safe for the logger's writes and the
// test's reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// captureLog sends Headscale's log to the returned buffer for the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()

	buf := new(lockedBuffer)

	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf)

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	t.Cleanup(func() {
		log.Logger = prev

		zerolog.SetGlobalLevel(prevLevel)
	})

	return buf
}

// lostPingCloses reads the lost-PING close count from the default registry.
func lostPingCloses(t *testing.T) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != "headscale_noise_http2_errors_total" {
			continue
		}

		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "type" && label.GetValue() == "conn_close_lost_ping" {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}

	return 0
}

// TestServeNoiseHTTP2ClosesSilentClient serves a Noise-style HTTP/2
// connection to a client that completes the handshake and then reads
// nothing more, as a node whose network path is lost. The server must send
// a PING, close the connection when no answer comes, log the close as a
// warning through Headscale's logger, and count it.
func TestServeNoiseHTTP2ClosesSilentClient(t *testing.T) {
	logs := captureLog(t)
	lostBefore := lostPingCloses(t)

	serverConn, clientConn := net.Pipe()

	served := make(chan struct{})

	go func() {
		defer close(served)

		serveNoiseHTTP2(serverConn, http.NotFoundHandler(), types.NoiseConfig{
			PingAfterIdle: 100 * time.Millisecond,
			PingTimeout:   100 * time.Millisecond,
		})
	}()

	// Client preface and SETTINGS, then silence: the client never reads,
	// so it never answers the PING.
	_, err := clientConn.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)

	go func() {
		_ = http2.NewFramer(clientConn, nil).WriteSettings()
	}()

	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not close the silent connection")
	}

	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), `"component":"noise-http2"`)
	assert.Contains(t, logs.String(), "timeout waiting for PING response")
	assert.InDelta(t, lostBefore+1, lostPingCloses(t), 0)
}
