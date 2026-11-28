package servicecall

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// HTTPPolicy adds exchange deadlines; existing security/context deadlines always win.
// Zero header/idle values select 60s; zero RequestTimeout disables only that budget.
type HTTPPolicy struct{ ResponseHeaderTimeout, BodyIdleTimeout, RequestTimeout time.Duration }
type GlobalRate struct{ PerSecond, Burst int }
type requestBucket struct {
	mu      sync.Mutex
	limit   GlobalRate
	tokens  float64
	updated time.Time
}

func newRequestBucket(l GlobalRate) (*requestBucket, error) {
	if l == (GlobalRate{}) {
		return nil, nil
	}
	if l.PerSecond < 1 || l.Burst < 1 || int64(l.PerSecond) > 2147483647 || int64(l.Burst) > 2147483647 {
		return nil, ErrConfig
	}
	return &requestBucket{limit: l, tokens: float64(l.Burst), updated: time.Now()}, nil
}
func (b *requestBucket) take(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.updated) {
		b.tokens = min(float64(b.limit.Burst), b.tokens+now.Sub(b.updated).Seconds()*float64(b.limit.PerSecond))
		b.updated = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
func (p HTTPPolicy) normalized() (HTTPPolicy, error) {
	if p.ResponseHeaderTimeout < 0 || p.BodyIdleTimeout < 0 || p.RequestTimeout < 0 {
		return p, ErrConfig
	}
	if p.ResponseHeaderTimeout == 0 {
		p.ResponseHeaderTimeout = time.Minute
	}
	if p.BodyIdleTimeout == 0 {
		p.BodyIdleTimeout = time.Minute
	}
	return p, nil
}

var (
	errRequestTimeout = errors.New("outgate: HTTP request timeout")
	errHeaderTimeout  = errors.New("outgate: response header timeout")
	errUploadIdle     = errors.New("outgate: upload idle timeout")
	errDownloadIdle   = errors.New("outgate: downstream idle timeout")
)

type ingressHandler struct {
	next   http.Handler
	bucket *requestBucket
	policy HTTPPolicy
}

func (h *ingressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.bucket.take(time.Now()) {
		reject(w, http.StatusTooManyRequests)
		return
	}
	if h.policy.RequestTimeout > 0 {
		ctx, cancel := context.WithTimeoutCause(r.Context(), h.policy.RequestTimeout, errRequestTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}
	h.next.ServeHTTP(w, r)
}

// ComposeRuntimeHandler keeps the listener's rate/overall-deadline boundary
// outside runtime readiness checks. The original gate is applied exactly once.
// Arbitrary handlers (including lifecycle-test handlers) are wrapped normally.
func ComposeRuntimeHandler(h http.Handler, wrap func(http.Handler) http.Handler) http.Handler {
	if ingress, ok := h.(*ingressHandler); ok {
		return &ingressHandler{next: wrap(ingress.next), bucket: ingress.bucket, policy: ingress.policy}
	}
	return wrap(h)
}
func rejectRequest(w http.ResponseWriter, r *http.Request, status int) {
	reject(w, timeoutStatus(r.Context(), status))
}
func timeoutStatus(ctx context.Context, fallback int) int {
	switch context.Cause(ctx) {
	case errRequestTimeout, errHeaderTimeout, errDownloadIdle, context.DeadlineExceeded:
		return http.StatusGatewayTimeout
	case errUploadIdle:
		return http.StatusRequestTimeout
	default:
		return fallback
	}
}

type headerWatch struct {
	mu       sync.Mutex
	timer    *time.Timer
	done     bool
	duration time.Duration
	cancel   context.CancelCauseFunc
}

func (h *headerWatch) arm() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.done && h.timer == nil {
		h.timer = time.AfterFunc(h.duration, func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if !h.done {
				h.cancel(errHeaderTimeout)
			}
		})
	}
}
func (h *headerWatch) stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.done = true
	if h.timer != nil {
		h.timer.Stop()
	}
}

// idleBody times only active blocking reads. Backpressure between reads does not
// create a second reader, pump data, or buffer a body. Reader/Close retain their
// ordinary cooperative cancellation contract.
type idleBody struct {
	io.ReadCloser
	ctx            context.Context
	idle           time.Duration
	cancel         context.CancelCauseFunc
	cause          error
	ioState        *exchangeIO
	remaining      int64
	headers        *headerWatch
	uploadComplete bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.uploadComplete {
		return 0, io.EOF
	}
	if b.ctx.Err() != nil {
		return 0, context.Cause(b.ctx)
	}
	idleUntil := time.Now().Add(b.idle)
	readUntil := idleUntil
	if hard, ok := b.ctx.Deadline(); ok && hard.Before(readUntil) {
		readUntil = hard
	}
	if b.ioState != nil && !b.ioState.armRead(b.ctx, readUntil) {
		return 0, context.Cause(b.ctx)
	}
	timer := time.AfterFunc(time.Until(idleUntil), func() { b.cancel(b.cause) })
	n, err := b.ReadCloser.Read(p)
	timer.Stop()
	if n > 0 && b.remaining > 0 {
		b.remaining -= int64(n)
	}
	if b.headers != nil && (err == io.EOF || b.remaining == 0) {
		b.uploadComplete = true
		if b.ioState != nil {
			b.ioState.finishUpload(b.ctx)
		}
		b.headers.arm()
	}
	if !time.Now().Before(readUntil) {
		if hard, ok := b.ctx.Deadline(); ok && !time.Now().Before(hard) && hard.Before(idleUntil) {
			b.cancel(context.DeadlineExceeded)
		} else if !time.Now().Before(idleUntil) {
			b.cancel(b.cause)
		}
	}
	if b.ctx.Err() != nil {
		return n, context.Cause(b.ctx)
	}
	return n, err
}
func operationDeadline(ctx context.Context, idle time.Duration) time.Time {
	d := time.Now().Add(idle)
	if hard, ok := ctx.Deadline(); ok && hard.Before(d) {
		return hard
	}
	return d
}

type timedTransport struct {
	next    http.RoundTripper
	ctx     context.Context
	cancel  context.CancelCauseFunc
	policy  HTTPPolicy
	ioState *exchangeIO
}

func (t timedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	watch := &headerWatch{duration: t.policy.ResponseHeaderTimeout, cancel: t.cancel}
	defer watch.stop()
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		watch.arm()
	} else {
		r.Body = &idleBody{ReadCloser: r.Body, ctx: t.ctx, idle: t.policy.BodyIdleTimeout, cancel: t.cancel, cause: errUploadIdle, ioState: t.ioState, remaining: r.ContentLength, headers: watch}
	}
	response, err := t.next.RoundTrip(r)
	watch.stop()
	if t.ctx.Err() != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, context.Cause(t.ctx)
	}
	if err != nil {
		return response, err
	}
	if response != nil && response.Body != nil {
		response.Body = &idleBody{ReadCloser: response.Body, ctx: t.ctx, idle: t.policy.BodyIdleTimeout, cancel: t.cancel, cause: errDownloadIdle, remaining: -1}
	}
	return response, nil
}

// exchangeIO serializes deadline arming with cancellation so a later arm cannot
// accidentally replace a cancellation deadline with a future one.
type exchangeIO struct {
	mu                sync.Mutex
	controller        *http.ResponseController
	canceled, writing bool
	failure           error
	cancel            context.CancelCauseFunc
}

func (s *exchangeIO) fail(reason error) {
	s.mu.Lock()
	if s.failure == nil {
		s.failure = reason
	}
	s.mu.Unlock()
	s.cancel(reason)
}
func (s *exchangeIO) status(ctx context.Context, fallback int) int {
	s.mu.Lock()
	reason := s.failure
	s.mu.Unlock()
	switch reason {
	case errUploadIdle:
		return http.StatusRequestTimeout
	case errHeaderTimeout, errDownloadIdle, errRequestTimeout, context.DeadlineExceeded:
		return http.StatusGatewayTimeout
	default:
		return timeoutStatus(ctx, fallback)
	}
}
func (s *exchangeIO) armRead(ctx context.Context, deadline time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canceled || ctx.Err() != nil {
		return false
	}
	_ = s.controller.SetReadDeadline(deadline)
	return true
}
func (s *exchangeIO) finishUpload(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canceled && ctx.Err() == nil {
		_ = s.controller.SetReadDeadline(time.Time{})
	}
}
func (s *exchangeIO) armWrite(ctx context.Context, idle time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canceled || ctx.Err() != nil {
		return false
	}
	_ = s.controller.SetWriteDeadline(operationDeadline(ctx, idle))
	s.writing = true
	return true
}
func (s *exchangeIO) finishWrite() { s.mu.Lock(); s.writing = false; s.mu.Unlock() }
func (s *exchangeIO) abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canceled = true
	_ = s.controller.SetReadDeadline(time.Now())
	if s.writing {
		_ = s.controller.SetWriteDeadline(time.Now())
	}
}

type deadlineWriter struct {
	http.ResponseWriter
	ctx     context.Context
	idle    time.Duration
	cancel  context.CancelCauseFunc
	ioState *exchangeIO
}

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *deadlineWriter) Write(p []byte) (int, error) {
	if !w.ioState.armWrite(w.ctx, w.idle) {
		return 0, context.Cause(w.ctx)
	}
	defer w.ioState.finishWrite()
	timer := time.AfterFunc(w.idle, func() { w.cancel(errDownloadIdle) })
	defer timer.Stop()
	return w.ResponseWriter.Write(p)
}
func (w *deadlineWriter) FlushError() error {
	if !w.ioState.armWrite(w.ctx, w.idle) {
		return context.Cause(w.ctx)
	}
	defer w.ioState.finishWrite()
	timer := time.AfterFunc(w.idle, func() { w.cancel(errDownloadIdle) })
	defer timer.Stop()
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// RequestStatus maps a request deadline to an HTTP error before response headers.
// A runtime wrapper can use it for readiness failures inside this ingress budget.
func RequestStatus(ctx context.Context, fallback int) int { return timeoutStatus(ctx, fallback) }
