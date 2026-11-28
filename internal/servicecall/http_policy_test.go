package servicecall

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate/internal/registry"
)

func customTransport(f *fixture, send func(*http.Request) (*http.Response, error)) {
	f.config.Resolve = func(_ context.Context, _ registry.Decision) (Recipient, error) {
		return Recipient{Key: f.recipient, Transport: transport{handle: f.selected, send: send}}, nil
	}
}
func TestGlobalRateBeforeRuntimeAndExactlyOnce(t *testing.T) {
	f := testFixture(t)
	f.config.GlobalRate = GlobalRate{PerSecond: 1, Burst: 1}
	server, err := NewServer(f.config)
	must(t, err)
	bucket := server.Handler.(*ingressHandler).bucket
	bucket.updated = time.Now().Add(time.Hour)
	var ready atomic.Int32
	server.Handler = ComposeRuntimeHandler(server.Handler, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ready.Add(1); next.ServeHTTP(w, r) })
	})
	address, client := runServer(t, server, f.clientTLS)
	first, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
	must(t, err)
	defer first.Body.Close()
	second, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
	must(t, err)
	defer second.Body.Close()
	if first.StatusCode != 200 || second.StatusCode != 429 || ready.Load() != 1 || f.replay.count() != 1 || f.calls.Load() != 1 {
		t.Fatal("rate boundary misplaced or double charged", first.StatusCode, second.StatusCode, ready.Load(), f.replay.count())
	}
}
func TestRateRefillAndConcurrentBoundary(t *testing.T) {
	bucket, err := newRequestBucket(GlobalRate{PerSecond: 2, Burst: 2})
	must(t, err)
	now := bucket.updated
	if !bucket.take(now) || !bucket.take(now) || bucket.take(now) {
		t.Fatal("burst")
	}
	if !bucket.take(now.Add(time.Second/2)) || bucket.take(now.Add(time.Second/2)) {
		t.Fatal("refill")
	}
	if bucket.take(now) {
		t.Fatal("clock rollback refilled bucket")
	}
	for _, limit := range []GlobalRate{{PerSecond: 1}, {Burst: 1}, {PerSecond: -1, Burst: 1}} {
		if _, err := newRequestBucket(limit); err != ErrConfig {
			t.Fatal(err)
		}
	}
}
func TestResponseHeadersAndOverallTimeouts(t *testing.T) {
	for _, kind := range []string{"headers", "overall_admission"} {
		t.Run(kind, func(t *testing.T) {
			f := testFixture(t)
			if kind == "headers" {
				f.config.HTTP.ResponseHeaderTimeout = 30 * time.Millisecond
				customTransport(f, func(r *http.Request) (*http.Response, error) {
					_, _ = io.Copy(io.Discard, r.Body)
					_ = r.Body.Close()
					<-r.Context().Done()
					return nil, r.Context().Err()
				})
			} else {
				f.config.HTTP.RequestTimeout = 30 * time.Millisecond
				f.config.Authenticate = func(ctx context.Context, _ Peer, _, _ string) (delivery.Key, error) {
					<-ctx.Done()
					return delivery.Key{}, ctx.Err()
				}
			}
			server, err := NewServer(f.config)
			must(t, err)
			address, client := runServer(t, server, f.clientTLS)
			response, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
			must(t, err)
			defer response.Body.Close()
			if response.StatusCode != 504 {
				t.Fatal(response.StatusCode)
			}
			if kind == "overall_admission" && f.replay.count() != 0 {
				t.Fatal("timed out admission dispatched")
			}
		})
	}
}

type pacedBody struct {
	ctx       context.Context
	delay     time.Duration
	remaining int
}

func (b *pacedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	timer := time.NewTimer(b.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		b.remaining--
		return copy(p, "data: tick\n\n"), nil
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}
func (*pacedBody) Close() error { return nil }
func TestSSEOutlivesHeaderBudgetAndRespectsBodyIdle(t *testing.T) {
	for _, idle := range []bool{false, true} {
		t.Run(fmt.Sprint(idle), func(t *testing.T) {
			f := testFixture(t)
			f.config.HTTP.ResponseHeaderTimeout = 100 * time.Millisecond
			f.config.HTTP.BodyIdleTimeout = time.Second
			if idle {
				f.config.HTTP.BodyIdleTimeout = 60 * time.Millisecond
			}
			customTransport(f, func(r *http.Request) (*http.Response, error) {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
				delay := 30 * time.Millisecond
				if idle {
					delay = time.Hour
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: &pacedBody{ctx: r.Context(), delay: delay, remaining: 6}, ContentLength: -1}, nil
			})
			server, err := NewServer(f.config)
			must(t, err)
			address, client := runServer(t, server, f.clientTLS)
			response, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
			must(t, err)
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if response.StatusCode != 200 {
				t.Fatal(response.StatusCode)
			}
			if idle {
				if err == nil {
					t.Fatal("idle SSE completed normally")
				}
			} else if err != nil || strings.Count(string(data), "data: tick") != 6 {
				t.Fatal("active SSE cut by header timer", string(data), err)
			}
		})
	}
}
func TestUploadIdleReturns408WithoutReadingWholeBody(t *testing.T) {
	f := testFixture(t)
	f.config.HTTP.BodyIdleTimeout = 40 * time.Millisecond
	customTransport(f, func(r *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		return nil, err
	})
	server, err := NewServer(f.config)
	must(t, err)
	address, _ := runServer(t, server, f.clientTLS)
	parsed, err := url.Parse(address)
	must(t, err)
	conn, err := tls.Dial("tcp", parsed.Host, f.clientTLS)
	must(t, err)
	defer conn.Close()
	must(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	req := signedRequest(t, address, publicURI, callerID, 0, f.call)
	_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 8\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host)
	must(t, err)
	must(t, req.Header.Write(conn))
	_, err = io.WriteString(conn, "\r\n")
	must(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	must(t, err)
	defer response.Body.Close()
	if response.StatusCode != 408 {
		t.Fatal(response.StatusCode)
	}
}
func TestPolicyValidationAndRuntimeDeadlineStatus(t *testing.T) {
	if _, err := (HTTPPolicy{BodyIdleTimeout: -1}).normalized(); err != ErrConfig {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errRequestTimeout)
	if RequestStatus(ctx, 503) != 504 || !errors.Is(context.Cause(ctx), errRequestTimeout) {
		t.Fatal("runtime deadline status")
	}
	h := &ingressHandler{next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		http.Error(w, "unavailable", RequestStatus(r.Context(), 503))
	}), policy: HTTPPolicy{RequestTimeout: time.Millisecond}}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest("GET", "https://gateway.test/", nil))
	if out.Code != 504 {
		t.Fatal(out.Code)
	}
}

func TestHeaderTimerWaitsForUploadAndNoRetry(t *testing.T) {
	f := testFixture(t)
	f.config.HTTP.ResponseHeaderTimeout = 10 * time.Millisecond
	f.config.HTTP.BodyIdleTimeout = 100 * time.Millisecond
	var calls atomic.Int32
	customTransport(f, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		// Waiting before consuming upload is transport backpressure, not response-header wait.
		timer := time.NewTimer(40 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		_, err := io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2}, nil
	})
	server, err := NewServer(f.config)
	must(t, err)
	address, client := runServer(t, server, f.clientTLS)
	response, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
	must(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	must(t, err)
	if response.StatusCode != 200 || string(data) != "ok" || calls.Load() != 1 {
		t.Fatal("upload charged as header wait or retried", response.StatusCode, string(data), calls.Load())
	}
}
func TestOverallDeadlineDoesNotExtendSecurityLease(t *testing.T) {
	f := testFixture(t)
	f.config.HTTP.RequestTimeout = time.Hour
	f.config.Authorize = func(context.Context, Call) (time.Time, error) { return time.Now().Add(250 * time.Millisecond), nil }
	ended := make(chan error, 1)
	customTransport(f, func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		<-r.Context().Done()
		ended <- context.Cause(r.Context())
		return nil, r.Context().Err()
	})
	server, err := NewServer(f.config)
	must(t, err)
	address, client := runServer(t, server, f.clientTLS)
	response, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != 504 {
			t.Fatal(response.StatusCode)
		}
	}
	select {
	case cause := <-ended:
		if !errors.Is(cause, context.DeadlineExceeded) {
			t.Fatal(cause)
		}
	case <-time.After(time.Second):
		t.Fatal("security lease did not cancel exchange")
	}
}
func TestOverallDeadlineAbortsActiveSSE(t *testing.T) {
	f := testFixture(t)
	f.config.HTTP = HTTPPolicy{ResponseHeaderTimeout: 10 * time.Millisecond, BodyIdleTimeout: time.Second, RequestTimeout: 200 * time.Millisecond}
	customTransport(f, func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: &pacedBody{ctx: r.Context(), delay: 20 * time.Millisecond, remaining: 100}, ContentLength: -1}, nil
	})
	server, err := NewServer(f.config)
	must(t, err)
	address, client := runServer(t, server, f.clientTLS)
	response, err := client.Do(signedRequest(t, address, publicURI, callerID, 0, f.call))
	must(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if response.StatusCode != 200 || err == nil || strings.Count(string(data), "data: tick") >= 100 {
		t.Fatal("overall timeout did not abort active stream", response.StatusCode, len(data), err)
	}
}

func TestGlobalRateConcurrentBurst(t *testing.T) {
	bucket, err := newRequestBucket(GlobalRate{PerSecond: 1, Burst: 8})
	must(t, err)
	now := bucket.updated
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if bucket.take(now) {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 8 {
		t.Fatal("concurrent burst exceeded limit", accepted.Load())
	}
}
