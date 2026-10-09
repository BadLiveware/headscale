package hscontrol

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// The HTTP/2 server's messages, such as the close after a lost PING, must
// reach Headscale's logger.
func TestNoiseHTTP2ErrorLogUsesZerolog(t *testing.T) {
	var buf bytes.Buffer

	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	t.Cleanup(func() {
		log.Logger = prev

		zerolog.SetGlobalLevel(prevLevel)
	})

	noiseHTTP2ErrorLog.Print("timeout waiting for PING response")

	assert.Contains(t, buf.String(), `"level":"info"`)
	assert.Contains(t, buf.String(), `"component":"noise-http2"`)
	assert.Contains(t, buf.String(), `"message":"timeout waiting for PING response"`)
}
