package servertest

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// An empty read on a cut connection returns at once instead of spinning.
func TestCuttableConnEmptyReadReturns(t *testing.T) {
	a, b := net.Pipe()

	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	cut := new(atomic.Bool)
	cut.Store(true)

	conn := &cuttableConn{Conn: a, cut: cut}

	done := make(chan struct{})

	go func() {
		defer close(done)

		_, _ = conn.Read(nil)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("empty read on a cut connection did not return")
	}
}
