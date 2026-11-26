package servicecall

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

func requestMetadata(req *http.Request) (httpsig.Request, http.Header, error) {
	u := req.URL
	if u == nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" ||
		len(req.RequestURI) > v1.MaxRawURIBytes || len(u.Path) > v1.MaxRawURIBytes || len(u.RawPath) > v1.MaxRawURIBytes ||
		len(u.RawQuery) > v1.MaxRawURIBytes || u.RequestURI() != req.RequestURI || u.RawPath != "" && u.EscapedPath() != u.RawPath ||
		len(req.Header) > 256 || len(req.Trailer) != 0 {
		return httpsig.Request{}, nil, httpsig.ErrAuth
	}
	count, total := 0, 2
	for name, values := range req.Header {
		if len(name) > 128 || len(values) == 0 || len(values) > 256-count {
			return httpsig.Request{}, nil, httpsig.ErrAuth
		}
		count += len(values)
		for _, value := range values {
			if len(value) > 32768 {
				return httpsig.Request{}, nil, httpsig.ErrAuth
			}
			total += len(name) + len(value) + 4
			if total > 32768 {
				return httpsig.Request{}, nil, httpsig.ErrAuth
			}
		}
	}
	metadata := httpsig.Request{Method: req.Method, Scheme: "https", Authority: req.Host, RawURI: req.RequestURI,
		Headers: make([]v1.Header, 0, count)}
	signed := make(http.Header, 5)
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		switch lower {
		case "signature-input", "x-outgate-caller-service", "x-outgate-target-service", "x-outgate-deployment-grant-id", "x-outgate-expected-route-revision":
			if len(values) != 1 || signed.Get(name) != "" || values[0] == "" {
				return httpsig.Request{}, nil, httpsig.ErrAuth
			}
			signed.Set(name, values[0])
		}
		// An HTTP/1.1 Connection: close from the caller describes this hop.
		if lower == "connection" && len(values) == 1 && strings.EqualFold(values[0], "close") {
			continue
		}
		for _, value := range values {
			metadata.Headers = append(metadata.Headers, v1.Header{lower, value})
		}
	}
	if v1.ValidateHTTPRequestMetadata(req.Method, req.Host, req.RequestURI, metadata.Headers) != nil {
		return httpsig.Request{}, nil, httpsig.ErrAuth
	}
	return metadata, signed, nil
}

func isForwardingHeader(name string) bool {
	switch name {
	case "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
		return true
	default:
		return false
	}
}

func (h *handler) outgoing(req *http.Request, metadata httpsig.Request, route registry.Decision, key delivery.Key) (*http.Request, error) {
	instance := route.Session.Instance()
	headers := metadata.Headers[:0]
	for _, pair := range metadata.Headers {
		if pair[0] == "signature" || pair[0] == "signature-input" || isForwardingHeader(pair[0]) {
			continue
		}
		headers = append(headers, pair)
	}
	headers = append(headers, v1.Header{"x-tunnel-instance", instance.InstanceID}, v1.Header{"x-tunnel-version", instance.Version},
		v1.Header{"x-forwarded-prefix", route.Prefix},
		v1.Header{"x-forwarded-host", req.Host}, v1.Header{"x-forwarded-proto", "https"})
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && net.ParseIP(host) != nil {
		headers = append(headers, v1.Header{"x-forwarded-for", host})
	}
	metadata.Headers = headers
	signature, err := h.signer.Sign(metadata, key.ID, key.Secret, time.Now())
	if err != nil {
		return nil, err
	}
	outgoing := req.Clone(req.Context())
	outgoing.URL.Scheme, outgoing.URL.Host = "https", req.Host
	outgoing.RequestURI = ""
	outgoing.Header = make(http.Header, len(headers)+2)
	for _, pair := range headers {
		outgoing.Header.Add(pair[0], pair[1])
	}
	outgoing.Header.Set("Signature", signature.Signature)
	outgoing.Header.Set("Signature-Input", signature.SignatureInput)
	return outgoing, nil
}
