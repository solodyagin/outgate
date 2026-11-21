package dependencies_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	_ "modernc.org/sqlite"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func loopbackTLS(t *testing.T) (server, client *tls.Config, ca []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Pin the public API entry points needed for the separate reverse HTTP/3 spike.
var (
	_ func(*http3.Transport, *quic.Conn) *http3.ClientConn = (*http3.Transport).NewClientConn
	_ func(*http3.Server, *quic.Conn) error                = (*http3.Server).ServeQUICConn
)

func TestQUICBootstrapStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	serverTLS, clientTLS, _ := loopbackTLS(t)
	serverTLS.NextProtos, clientTLS.NextProtos = []string{"outgate-tunnel/1"}, []string{"outgate-tunnel/1"}

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	must(t, err)
	defer listener.Close()
	service, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, nil)
	must(t, err)
	defer service.CloseWithError(0, "")
	gateway, err := listener.Accept(ctx)
	must(t, err)
	defer gateway.CloseWithError(0, "")
	if got := gateway.ConnectionState().TLS.NegotiatedProtocol; got != "outgate-tunnel/1" {
		t.Fatalf("unexpected ALPN %q", got)
	}

	bootstrap, err := service.OpenStreamSync(ctx)
	must(t, err)
	deadline, _ := ctx.Deadline()
	must(t, bootstrap.SetDeadline(deadline))
	_, err = bootstrap.Write([]byte("bootstrap"))
	must(t, err)
	carrier, err := gateway.AcceptStream(ctx)
	must(t, err)
	must(t, carrier.SetDeadline(deadline))
	payload := make([]byte, len("bootstrap"))
	_, err = io.ReadFull(carrier, payload)
	must(t, err)
	if bootstrap.StreamID() != 0 || carrier.StreamID() != 0 || string(payload) != "bootstrap" {
		t.Fatal("bootstrap did not arrive on client bidi stream 0")
	}
}

func TestWSSSubprotocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	serverTLS, clientTLS, _ := loopbackTLS(t)
	const subprotocol = "outgate.tunnel.v1"
	serverError := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(w, request, &websocket.AcceptOptions{
			Subprotocols: []string{subprotocol}, CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			serverError <- err
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(64)
		kind, payload, err := conn.Read(ctx)
		if err == nil {
			err = conn.Write(ctx, kind, payload)
		}
		serverError <- err
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	conn, response, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport}, Subprotocols: []string{subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	must(t, err)
	defer conn.CloseNow()
	if conn.Subprotocol() != subprotocol || response.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("WSS selected the wrong subprotocol or negotiated an extension")
	}
	must(t, conn.Write(ctx, websocket.MessageBinary, []byte("chunk")))
	kind, data, err := conn.Read(ctx)
	must(t, err)
	if kind != websocket.MessageBinary || string(data) != "chunk" {
		t.Fatal("binary WSS message changed")
	}
	select {
	case err := <-serverError:
		must(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSQLiteWALFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "outgate.db")
	uriPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" {
		uriPath = "/" + uriPath
	}
	query := url.Values{"_pragma": {"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(1000)"}}
	dsn := (&url.URL{Scheme: "file", Path: uriPath, RawQuery: query.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	must(t, err)
	defer db.Close()
	db.SetMaxOpenConns(2)
	writer, err := db.Conn(ctx)
	must(t, err)
	defer writer.Close()
	var engineVersion string
	must(t, writer.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&engineVersion))
	if engineVersion != "3.54.1" {
		t.Fatalf("unexpected embedded SQLite version %s", engineVersion)
	}
	reader, err := db.Conn(ctx)
	must(t, err)
	defer reader.Close()
	for _, conn := range []*sql.Conn{writer, reader} {
		var journal string
		var synchronous int
		must(t, conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal))
		must(t, conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous))
		if journal != "wal" || synchronous != 2 {
			t.Fatalf("expected WAL/FULL, got %s/%d", journal, synchronous)
		}
	}
	_, err = writer.ExecContext(ctx, "CREATE TABLE entries (id TEXT NOT NULL PRIMARY KEY)")
	must(t, err)
	tx, err := writer.BeginTx(ctx, nil)
	must(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "INSERT INTO entries VALUES (?)", "test-entry")
	must(t, err)
	var count int
	must(t, reader.QueryRowContext(ctx, "SELECT count(*) FROM entries").Scan(&count))
	if count != 0 {
		t.Fatal("uncommitted entry is visible on another connection")
	}
	must(t, tx.Commit())
	must(t, reader.QueryRowContext(ctx, "SELECT count(*) FROM entries").Scan(&count))
	if count != 1 {
		t.Fatal("committed entry is missing")
	}
	_, err = reader.ExecContext(ctx, "INSERT INTO entries VALUES (?)", "test-entry")
	if err == nil {
		t.Fatal("duplicate key was accepted")
	}
}

func TestPostgresVerifiedTLSConfig(t *testing.T) {
	_, _, ca := loopbackTLS(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	must(t, os.WriteFile(caFile, ca, 0600))
	// Keep the probe independent of the machine's libpq configuration.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(key), "PG") {
			original, _ := os.LookupEnv(key)
			must(t, os.Unsetenv(key))
			t.Cleanup(func() { must(t, os.Setenv(key, original)) })
		}
	}
	query := url.Values{
		"sslmode": {"verify-full"}, "sslrootcert": {caFile},
		"connect_timeout": {"5"}, "pool_max_conns": {"4"},
	}
	dsn := (&url.URL{
		Scheme: "postgres", Host: "db.example.test:5432", Path: "/outgate",
		User: url.UserPassword("probe", "fixture"), RawQuery: query.Encode(),
	}).String()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("cannot parse PostgreSQL probe configuration")
	}
	conn := cfg.ConnConfig
	tlsConfig := conn.TLSConfig
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.ServerName != "db.example.test" ||
		tlsConfig.RootCAs == nil || len(conn.Fallbacks) != 0 ||
		conn.ConnectTimeout != 5*time.Second || cfg.MaxConns != 4 {
		t.Fatal("PostgreSQL configuration lost an explicit TLS or resource constraint")
	}
	// This is a Go TLS setting; pgx's min_protocol_version refers to PostgreSQL.
	tlsConfig.MinVersion = tls.VersionTLS13
	if copied := conn.Copy().TLSConfig; copied.MinVersion != tls.VersionTLS13 || copied.InsecureSkipVerify {
		t.Fatal("copying the PostgreSQL configuration lost the TLS policy")
	}
}
