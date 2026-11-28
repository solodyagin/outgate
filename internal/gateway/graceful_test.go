package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGracefulShutdownWaitsForHTTPAndTunnelTogether(t *testing.T) {
	for _, first := range []string{"http", "tunnel"} {
		t.Run(first, func(t *testing.T) {
			entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			tunnelDone := make(chan struct{})
			began := make(chan time.Time, 1)
			owner := &testOwner{stop: make(chan struct{}), drain: func(deadline time.Time) <-chan struct{} { began <- deadline; return tunnelDone }}
			r, client, url, served := lifecycleRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				close(entered)
				<-release
				if req.Context().Err() != nil {
					t.Error("active HTTP canceled before grace")
				}
				_, _ = w.Write([]byte("completed"))
				close(handlerDone)
			}), owner)
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
				select {
				case <-tunnelDone:
				default:
					close(tunnelDone)
				}
			})
			eventually(t, func() bool { return r.Ready(t.Context()) == nil })
			responseDone := make(chan struct{})
			go func() {
				defer close(responseDone)
				response, err := client.Get(url)
				if err != nil {
					t.Error(err)
					return
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || string(body) != "completed" {
					t.Error("incomplete response", err, string(body))
				}
			}()
			await(t, entered)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- r.GracefulShutdown(ctx) }()
			deadline := <-began
			want, _ := ctx.Deadline()
			if !deadline.Equal(want) {
				t.Fatal("listeners did not share deadline", deadline, want)
			}
			if r.Ready(t.Context()) == nil {
				t.Fatal("draining runtime ready")
			}
			recorder := httptest.NewRecorder()
			r.server.Handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
			if recorder.Code != 503 {
				t.Fatal("admitted during grace")
			}
			if first == "http" {
				close(release)
				await(t, handlerDone)
				await(t, responseDone)
			} else {
				close(tunnelDone)
			}
			select {
			case <-owner.stop:
				t.Fatal("first listener completion stopped sibling")
			default:
			}
			if first == "http" {
				close(tunnelDone)
			} else {
				close(release)
			}
			check(t, <-result)
			await(t, responseDone)
			if !owner.closed.Load() {
				t.Fatal("stores not released after owners")
			}
			select {
			case <-served:
			case <-time.After(3 * time.Second):
				t.Fatal("Serve did not end")
			}
		})
	}
}

func TestGracefulDeadlineForcesButRetainsActiveOwner(t *testing.T) {
	entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	tunnelDone := make(chan struct{})
	began := make(chan time.Time, 1)
	owner := &testOwner{stop: make(chan struct{}), drain: func(deadline time.Time) <-chan struct{} { began <- deadline; return tunnelDone }}
	r, client, url, _ := lifecycleRuntime(t, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		close(entered)
		<-req.Context().Done()
		close(canceled)
		<-release
	}), owner)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	eventually(t, func() bool { return r.Ready(t.Context()) == nil })
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
		}
	}()
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if !errors.Is(r.GracefulShutdown(ctx), context.DeadlineExceeded) {
		t.Fatal("expected caller deadline")
	}
	<-began
	await(t, canceled)
	if owner.closed.Load() {
		t.Fatal("released stores under live handler")
	}
	close(release)
	check(t, r.Shutdown(t.Context()))
	await(t, requestDone)
}

func TestImmediateShutdownPreemptsDefaultGrace(t *testing.T) {
	began := make(chan time.Time, 1)
	pending := make(chan struct{})
	owner := &testOwner{stop: make(chan struct{}), drain: func(deadline time.Time) <-chan struct{} { began <- deadline; return pending }}
	r, _, _, _ := lifecycleRuntime(t, http.NotFoundHandler(), owner)
	eventually(t, func() bool { return r.Ready(t.Context()) == nil })
	before := time.Now()
	result := make(chan error, 1)
	go func() { result <- r.GracefulShutdown(t.Context()) }()
	deadline := <-began
	if deadline.Before(before.Add(29*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatal("incorrect default grace", deadline)
	}
	check(t, r.Shutdown(t.Context()))
	check(t, <-result)
}

func TestListenerFailureDuringGraceForcesSibling(t *testing.T) {
	began := make(chan time.Time, 1)
	pending := make(chan struct{})
	failure := errors.New("UDP failed during grace")
	owner := &testOwner{stop: make(chan struct{}), failure: make(chan error, 1), drain: func(deadline time.Time) <-chan struct{} { began <- deadline; return pending }}
	r, _, _, served := lifecycleRuntime(t, http.NotFoundHandler(), owner)
	eventually(t, func() bool { return r.Ready(t.Context()) == nil })
	result := make(chan error, 1)
	go func() { result <- r.GracefulShutdown(t.Context()) }()
	<-began
	// Wait for HTTP Serve to intentionally end first. A later UDP failure must
	// still abort the grace period and be reported, rather than hidden by it.
	eventually(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.httpServing })
	owner.failure <- failure
	select {
	case err := <-served:
		if !errors.Is(err, failure) {
			t.Fatal("lost UDP error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failure did not abort grace")
	}
	check(t, <-result)
}
