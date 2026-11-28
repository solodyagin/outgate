package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/resourcebudget"
	"github.com/solodyagin/outgate/internal/servicecall"
)

func TestSharedResourceBudgetOwnedByComposer(t *testing.T) {
	c := sqliteConfig(t)
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 4, ConnectionsPerIP: 4, Bytes: 1 << 30})
	check(t, err)
	c.Resources = pool
	c.TCPConnectionBytes = 65536
	r, err := OpenSQLiteRuntime(t.Context(), c)
	check(t, err)
	if r.connectionLimits.Shared != pool || r.connectionLimits.ConnectionBytes != 65536 {
		t.Fatal("TCP budget not wired")
	}
	check(t, r.Shutdown(t.Context()))
	for _, change := range []func(*Config){
		func(c *Config) { c.Connections.Shared = pool },
		func(c *Config) { c.TunnelLimits.Shared = pool },
		func(c *Config) { c.TCPConnectionBytes = 0 },
		func(c *Config) { c.TCPConnectionBytes = 1<<30 + 1 },
		func(c *Config) { c.Resources = nil },
	} {
		invalid := c
		change(&invalid)
		if _, err := OpenSQLiteRuntime(t.Context(), invalid); err != servicecall.ErrConfig {
			t.Fatal("invalid shared budget accepted", err)
		}
	}
}

func TestGatewaySharesBudgetBetweenRealQUICAndTCP(t *testing.T) {
	c := sqliteConfig(t)
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 1, ConnectionsPerIP: 1, Bytes: 1 << 30})
	check(t, err)
	c.Resources = pool
	c.TCPConnectionBytes = 65536
	r, err := OpenSQLiteRuntime(t.Context(), c)
	check(t, err)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	check(t, err)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	check(t, err)
	served := make(chan error, 1)
	go func() { served <- r.Serve(tcp, udp) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		check(t, r.Shutdown(ctx))
		select {
		case <-served:
		case <-ctx.Done():
			t.Error("serve did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, udp.LocalAddr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.Tunnel.ClientRoots, Certificates: []tls.Certificate{c.Tunnel.Certificate}, NextProtos: []string{v1.QUICALPN}}, nil)
	check(t, err)
	defer conn.CloseWithError(0, "test_complete")
	eventually(t, func() bool { return pool.Stats().Connections == 1 })
	if pool.Stats().Bytes <= c.TCPConnectionBytes {
		t.Fatal("native reservation not charged", pool.Stats())
	}
	client, err := net.Dial("tcp", tcp.Addr().String())
	check(t, err)
	defer client.Close()
	check(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	var data [1]byte
	if _, err := client.Read(data[:]); err == nil {
		t.Fatal("TCP admitted while QUIC held pool")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("TCP not rejected before TLS", err)
	}
	check(t, conn.CloseWithError(0, "test_complete"))
	eventually(t, func() bool { return pool.Stats() == (resourcebudget.Stats{}) })
}
