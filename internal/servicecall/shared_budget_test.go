package servicecall

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/solodyagin/outgate/internal/resourcebudget"
)

type blockingCloseConn struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}
func TestSharedBudgetRetainedUntilTCPActuallyCloses(t *testing.T) {
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 1, ConnectionsPerIP: 1, Bytes: 10})
	must(t, err)
	lease, err := pool.Acquire(netip.MustParseAddr("192.0.2.1"), 10)
	must(t, err)
	server, client := net.Pipe()
	defer client.Close()
	underlying := &blockingCloseConn{Conn: server, entered: make(chan struct{}), release: make(chan struct{})}
	conn := &quotaConn{Conn: underlying, release: lease.Release}
	done := make(chan error, 2)
	go func() { done <- conn.Close() }()
	<-underlying.entered
	go func() { done <- conn.Close() }()
	if s := pool.Stats(); s.Connections != 1 || s.Bytes != 10 {
		t.Fatal("blocked close released budget", s)
	}
	close(underlying.release)
	for range 2 {
		select {
		case err := <-done:
			must(t, err)
		case <-time.After(time.Second):
			t.Fatal("close stuck")
		}
	}
	if s := pool.Stats(); s != (resourcebudget.Stats{}) {
		t.Fatal(s)
	}
}
func TestInvalidSharedBudgetListenerRetainsOwnership(t *testing.T) {
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 1, ConnectionsPerIP: 1, Bytes: 10})
	must(t, err)
	for _, limits := range []ConnectionLimits{{MaxConnections: 1, ConnectionsPerIP: 1, Shared: pool}, {MaxConnections: 1, ConnectionsPerIP: 1, Shared: pool, ConnectionBytes: 11}, {MaxConnections: 1, ConnectionsPerIP: 1, ConnectionBytes: 1}} {
		queue := &queuedListener{connections: make(chan net.Conn), done: make(chan struct{})}
		if _, err := LimitListener(queue, limits); err != ErrConfig {
			t.Fatal(err)
		}
		select {
		case <-queue.done:
			t.Fatal("rejected config took listener ownership")
		default:
		}
		_ = queue.Close()
	}
}
