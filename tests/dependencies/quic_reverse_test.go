package dependencies_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const (
	tunnelALPN      = "outgate-tunnel/1"
	requestIDHeader = "X-Tunnel-Request-ID"
	connectHost     = "outgate-app-channel.invalid:443"
)

type reverseSession struct {
	http           *http3.ClientConn
	serviceControl *quic.Stream
	gatewayControl *quic.Stream
}

func startReverseSession(t *testing.T, ctx context.Context, handler http.Handler) reverseSession {
	t.Helper()
	serverTLS, clientTLS, _ := loopbackTLS(t)
	serverTLS.NextProtos, clientTLS.NextProtos = []string{tunnelALPN}, []string{tunnelALPN}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	must(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	service, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, nil)
	must(t, err)
	t.Cleanup(func() { _ = service.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
	gateway, err := listener.Accept(ctx)
	must(t, err)
	t.Cleanup(func() { _ = gateway.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
	security := gateway.ConnectionState()
	if security.TLS.NegotiatedProtocol != tunnelALPN || security.TLS.Version != tls.VersionTLS13 || security.Used0RTT {
		t.Fatal("incorrect QUIC handshake profile")
	}

	register, ack := registrationFixtures(t)
	serviceControl, err := service.OpenStreamSync(ctx)
	must(t, err)
	deadline, _ := ctx.Deadline()
	must(t, serviceControl.SetDeadline(deadline))
	token := []byte("outgate-spike-fixture")
	must(t, v1.WriteBootstrap(serviceControl, v1.DevelopmentBearer, token))
	must(t, v1.WriteControl(serviceControl, register, v1.MaxControlBytes))
	gatewayControl, err := gateway.AcceptStream(ctx)
	must(t, err)
	must(t, gatewayControl.SetDeadline(deadline))
	if serviceControl.StreamID() != 0 || gatewayControl.StreamID() != 0 {
		t.Fatal("registration must use stream 0")
	}
	credential, err := v1.ReadBootstrap(gatewayControl, v1.DevelopmentBearer)
	must(t, err)
	if !bytes.Equal(credential, token) {
		t.Fatal("unexpected fixture credential")
	}
	body, err := v1.ReadControl(gatewayControl, v1.MaxControlBytes)
	must(t, err)
	reg, err := v1.DecodeRegister(body)
	must(t, err)
	must(t, v1.WriteControl(gatewayControl, ack, v1.MaxControlBytes))
	body, err = v1.ReadControl(serviceControl, v1.MaxControlBytes)
	must(t, err)
	accepted, err := v1.DecodeRegisterAck(body)
	must(t, err)
	must(t, accepted.ValidateForRegister(reg, v1.RegisterAckValidationOptions{Development: true}))

	// The gateway has consumed stream 0; the service owns the other end of
	// stream 0 locally, so ServeQUICConn accepts only gateway-created requests.
	server := &http3.Server{Handler: handler, MaxHeaderBytes: 32 * 1024}
	served := make(chan error, 1)
	go func() { served <- server.ServeQUICConn(service) }()
	t.Cleanup(func() {
		_ = gateway.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		select {
		case err := <-served:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("reverse HTTP/3 server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("reverse HTTP/3 server did not exit")
		}
		_ = server.Close()
	})

	transport := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 32 * 1024}
	client := transport.NewClientConn(gateway)
	select {
	case <-client.ReceivedSettings():
		if client.Settings().EnableDatagrams {
			t.Fatal("unexpected HTTP/3 datagrams")
		}
	case err := <-served:
		// Cleanup must still be able to observe the server's exit.
		served <- err
		t.Fatalf("reverse HTTP/3 server exited during SETTINGS: %v", err)
	case <-ctx.Done():
		t.Fatalf("reverse HTTP/3 SETTINGS: %v", ctx.Err())
	}
	return reverseSession{http: client, serviceControl: serviceControl, gatewayControl: gatewayControl}
}

func registrationFixtures(t *testing.T) (register, ack json.RawMessage) {
	t.Helper()
	data, err := os.ReadFile("../fixtures/protocol/v1/control-messages.json")
	must(t, err)
	var fixtures struct {
		Positive []json.RawMessage `json:"positive"`
	}
	must(t, json.Unmarshal(data, &fixtures))
	for _, fixture := range fixtures.Positive {
		var discriminator struct {
			Type string `json:"type"`
		}
		must(t, json.Unmarshal(fixture, &discriminator))
		switch discriminator.Type {
		case "register":
			register = fixture
		case "register_ack":
			ack = fixture
		}
	}
	if len(register) == 0 || len(ack) == 0 {
		t.Fatal("registration fixtures are missing")
	}
	return register, ack
}

func (s reverseSession) exchangeStatus(t *testing.T, sequence v1.U64) {
	t.Helper()
	status := v1.InstanceStatus{
		Type: "instance_status", Sequence: sequence, Ready: true, Code: "ready", ObservedAt: time.Now().Unix(),
	}
	jsonStatus, err := json.Marshal(status)
	must(t, err)
	must(t, v1.WriteControl(s.serviceControl, jsonStatus, v1.MaxControlBytes))
	body, err := v1.ReadControl(s.gatewayControl, v1.MaxControlBytes)
	must(t, err)
	got, err := v1.DecodeInstanceStatus(body)
	must(t, err)
	if got.Sequence != status.Sequence || got.Ready != status.Ready || got.Code != status.Code || got.ObservedAt != status.ObservedAt {
		t.Fatal("stream 0 status changed after HTTP/3 startup")
	}
}

func (s reverseSession) exchangeDrain(t *testing.T) {
	t.Helper()
	want := v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 30000, Code: "shutdown"}
	frame, err := json.Marshal(want)
	must(t, err)
	must(t, v1.WriteControl(s.gatewayControl, frame, v1.MaxControlBytes))
	frame, err = v1.ReadControl(s.serviceControl, v1.MaxControlBytes)
	must(t, err)
	got, err := v1.DecodeDrain(frame)
	must(t, err)
	if got.CommandID != want.CommandID || got.DeadlineMS != want.DeadlineMS || got.Code != want.Code {
		t.Fatal("gateway command changed on the control stream")
	}
}

func request(ctx context.Context, t *testing.T, id int, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	must(t, err)
	req.Header.Set(requestIDHeader, strconv.Itoa(id))
	return req
}

func readExact(t *testing.T, from io.Reader, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	_, err := io.ReadFull(from, buf)
	must(t, err)
	if string(buf) != want {
		t.Fatalf("got %q, want %q", buf, want)
	}
}

func await[T any](t *testing.T, ctx context.Context, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

func TestQUICReverseStreamingAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	type cancellationResult struct{ stream, handler error }
	cancellation := make(chan cancellationResult, 1)
	service := startReverseSession(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/стрим":
			if req.Method != http.MethodPost || req.ProtoMajor != 3 || req.Host != "public.example.test:8443" ||
				req.URL.EscapedPath() != "/api/%D1%81%D1%82%D1%80%D0%B8%D0%BC" ||
				req.URL.RawQuery != "tag=%2f&tag=one" || req.Header.Get(requestIDHeader) != "1" ||
				!slices.Equal(req.Header.Values("X-Probe"), []string{"first", "second"}) {
				http.Error(w, "forwarded request metadata changed", http.StatusBadRequest)
				return
			}
			first := make([]byte, len("upload-1"))
			if _, err := io.ReadFull(req.Body, first); err != nil || string(first) != "upload-1" {
				http.Error(w, "first upload chunk missing", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Add("Set-Cookie", "a=1")
			w.Header().Add("Set-Cookie", "b=2")
			if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			second := make([]byte, len("upload-2"))
			if _, err := io.ReadFull(req.Body, second); err != nil || string(second) != "upload-2" {
				return
			}
			if _, err := req.Body.Read(first[:1]); !errors.Is(err, io.EOF) {
				return
			}
			_, _ = io.WriteString(w, "data: second\n\n")
		case "/cancel":
			var first [1]byte
			if _, err := io.ReadFull(req.Body, first[:]); err != nil || first[0] != 'x' {
				http.Error(w, "missing upload byte", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			if err := http.NewResponseController(w).Flush(); err != nil {
				cancellation <- cancellationResult{stream: err}
				return
			}
			_, streamErr := req.Body.Read(first[:])
			<-req.Context().Done()
			cancellation <- cancellationResult{stream: streamErr, handler: req.Context().Err()}
		case "/after":
			_, _ = io.WriteString(w, "still connected")
		default:
			http.NotFound(w, req)
		}
	}))

	reader, writer := io.Pipe()
	defer writer.Close()
	stop := context.AfterFunc(ctx, func() { _ = writer.CloseWithError(ctx.Err()) })
	defer stop()
	req := request(ctx, t, 1, http.MethodPost, "https://public.example.test:8443/api/%D1%81%D1%82%D1%80%D0%B8%D0%BC?tag=%2f&tag=one", reader)
	req.Header.Add("X-Probe", "first")
	req.Header.Add("X-Probe", "second")
	type response struct {
		value *http.Response
		err   error
	}
	responses := make(chan response, 1)
	go func() {
		result, err := service.http.RoundTrip(req)
		responses <- response{result, err}
	}()
	_, err := io.WriteString(writer, "upload-1")
	must(t, err)
	result := await(t, ctx, responses)
	must(t, result.err)
	streaming := result.value
	defer streaming.Body.Close()
	if streaming.StatusCode != http.StatusOK || streaming.ProtoMajor != 3 ||
		streaming.Header.Get("Content-Type") != "text/event-stream" ||
		!slices.Equal(streaming.Header.Values("Set-Cookie"), []string{"a=1", "b=2"}) {
		t.Fatalf("unexpected streaming response: %d %v", streaming.StatusCode, streaming.Header)
	}
	// Receive the first flush while the upload is still open. Stream 0
	// remains usable during both directions of HTTP/3 DATA.
	readExact(t, streaming.Body, "data: first\n\n")
	service.exchangeStatus(t, 1)

	requestCtx, abort := context.WithCancel(ctx)
	defer abort()
	cancelRead, cancelWrite := io.Pipe()
	defer cancelWrite.Close()
	stopCancel := context.AfterFunc(requestCtx, func() { _ = cancelWrite.CloseWithError(requestCtx.Err()) })
	defer stopCancel()
	req = request(requestCtx, t, 2, http.MethodPost, "https://public.example.test/cancel", cancelRead)
	go func() {
		result, err := service.http.RoundTrip(req)
		responses <- response{result, err}
	}()
	_, err = io.WriteString(cancelWrite, "x")
	must(t, err)
	result = await(t, ctx, responses)
	must(t, result.err)
	defer result.value.Body.Close()
	if result.value.StatusCode != http.StatusOK {
		t.Fatalf("cancellation probe rejected: %d", result.value.StatusCode)
	}
	abort()
	cancelCause := await(t, ctx, cancellation)
	var streamError *quic.StreamError
	if !errors.Is(cancelCause.handler, context.Canceled) || !errors.As(cancelCause.stream, &streamError) ||
		streamError.ErrorCode != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
		t.Fatalf("handler did not receive H3_REQUEST_CANCELLED: stream=%v context=%v", cancelCause.stream, cancelCause.handler)
	}
	// The other HTTP/3 stream must still accept an upload and finish its response.
	_, err = io.WriteString(writer, "upload-2")
	must(t, err)
	must(t, writer.Close())
	readExact(t, streaming.Body, "data: second\n\n")
	_, err = streaming.Body.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("streaming response did not finish: %v", err)
	}

	followUp, err := service.http.RoundTrip(request(ctx, t, 3, http.MethodGet, "https://public.example.test/after", nil))
	must(t, err)
	defer followUp.Body.Close()
	readExact(t, followUp.Body, "still connected")
	service.exchangeStatus(t, 2)
	service.exchangeDrain(t)
}

func TestQUICReverseInternalConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const (
		upgrade = "GET /socket?protected=1 HTTP/1.1\r\nHost: app.example.test\r\nConnection: Upgrade\r\n" +
			"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
		switching = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
		// One masked client text frame and an unmasked server text frame.
		clientFrame = "\x81\x82\x01\x02\x03\x04\x69\x6b"
		serverFrame = "\x81\x02ok"
	)
	innerResult := make(chan error, 1)
	service := startReverseSession(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logicalID := req.Header.Get(requestIDHeader)
		if req.Method != http.MethodConnect || req.Host != connectHost || req.URL.Host != connectHost ||
			req.URL.Path != "" || req.URL.Scheme != "" || req.URL.RawQuery != "" ||
			req.Proto != "HTTP/3.0" || (logicalID != "1" && logicalID != "3") {
			http.Error(w, "invalid internal CONNECT", http.StatusBadRequest)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			innerResult <- errors.New("CONNECT has no HTTPStream")
			return
		}
		w.WriteHeader(http.StatusOK)
		stream, err := streamer.HTTPStream()
		if err != nil {
			innerResult <- err
			return
		}
		defer stream.Close()
		inner := bufio.NewReader(stream)
		appRequest, err := http.ReadRequest(inner)
		if err != nil {
			innerResult <- err
			return
		}
		defer appRequest.Body.Close()
		if appRequest.Host != "app.example.test" || appRequest.RequestURI != "/socket?protected=1" ||
			appRequest.Header.Get("Upgrade") != "websocket" ||
			appRequest.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
			innerResult <- errors.New("inner HTTP/1.1 handshake changed")
			return
		}
		if logicalID == "3" {
			_, err := io.WriteString(stream, "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden")
			innerResult <- err
			return
		}
		if _, err = io.WriteString(stream, switching); err != nil {
			innerResult <- err
			return
		}
		// FIN must only close the receive direction of the CONNECT.
		buf := make([]byte, len(clientFrame))
		if _, err := io.ReadFull(inner, buf); err != nil || string(buf) != clientFrame {
			innerResult <- fmt.Errorf("inner WebSocket frame mismatch: %v", err)
			return
		}
		if _, err := inner.ReadByte(); !errors.Is(err, io.EOF) {
			innerResult <- fmt.Errorf("expected CONNECT FIN: %v", err)
			return
		}
		_, err = io.WriteString(stream, serverFrame)
		innerResult <- err
	}))

	connect := func(target string, id int, wantStream quic.StreamID) (*http3.RequestStream, *http.Response) {
		t.Helper()
		stream, err := service.http.OpenRequestStream(ctx)
		must(t, err)
		deadline, _ := ctx.Deadline()
		must(t, stream.SetDeadline(deadline))
		if stream.StreamID() != wantStream {
			t.Fatalf("expected gateway stream ID %d, got %d", wantStream, stream.StreamID())
		}
		t.Cleanup(func() {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		})
		req := &http.Request{
			Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target},
			Header: http.Header{requestIDHeader: {strconv.Itoa(id)}},
		}
		must(t, stream.SendRequestHeader(req))
		response, err := stream.ReadResponse()
		must(t, err)
		return stream, response
	}
	tunnel, response := connect(connectHost, 1, 1)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("internal channel returned %d", response.StatusCode)
	}
	_, err := io.WriteString(tunnel, upgrade)
	must(t, err)
	appReader := bufio.NewReader(tunnel)
	appResponse, err := http.ReadResponse(appReader, &http.Request{Method: http.MethodGet})
	must(t, err)
	if appResponse.StatusCode != http.StatusSwitchingProtocols ||
		appResponse.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("inner handshake returned %d", appResponse.StatusCode)
	}
	_, err = io.WriteString(tunnel, clientFrame)
	must(t, err)
	must(t, tunnel.Close())
	readExact(t, appReader, serverFrame)
	if _, err := appReader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("CONNECT did not finish after response FIN: %v", err)
	}
	must(t, await(t, ctx, innerResult))
	service.exchangeStatus(t, 1)

	_, response = connect("untrusted.example.test:443", 2, 5)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected destination was accepted: %d", response.StatusCode)
	}
	must(t, response.Body.Close())

	denied, response := connect(connectHost, 3, 9)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected a byte channel before the inner refusal, got %d", response.StatusCode)
	}
	_, err = io.WriteString(denied, upgrade)
	must(t, err)
	innerRefusal, err := http.ReadResponse(bufio.NewReader(denied), &http.Request{Method: http.MethodGet})
	must(t, err)
	defer innerRefusal.Body.Close()
	if innerRefusal.StatusCode != http.StatusForbidden {
		t.Fatalf("expected an inner 403, got %d", innerRefusal.StatusCode)
	}
	readExact(t, innerRefusal.Body, "forbidden")
	must(t, await(t, ctx, innerResult))
}
