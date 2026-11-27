package servicecall

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

func TestMountLocations(t *testing.T) {
	for _, tc := range []struct{ prefix, uri, location, want string }{
		{"/api/v1", "/api/v1", "login", "/api/v1/login"},
		{"/api/v1", "/api/v1/", "/login?x=%2b&x=#part", "/api/v1/login?x=%2b&x=#part"},
		{"/api/v1", "/api/v1/a/b?old=1", "../login?", "/api/v1/login?"},
		{"/api/v1", "/api/v1/%69tems?x=%2b", "#part", "/api/v1/%69tems?x=%2b#part"},
		{"/api/v1", "/api/v1/items?", "#part", "/api/v1/items?#part"},
		{"/api/v1", "/api/v1/items?x=%2b", "#", "/api/v1/items?x=%2b#"},
		{"/api/v1", "/api/v1/items?", "#", "/api/v1/items?#"},
		{"/api/v1", "/api/v1/items", "/login?#", "/api/v1/login?#"},
		{"/api/v1", "/api/v1/a/b", "../../../../login", "/api/v1/login"},
		{"/api/v1", "/api/v1/a", "/a%252fb", "/api/v1/a%252fb"},
		{"/api/v1", "/api/v1", "https://other.example/login?q=1#f", "https://other.example/login?q=1#f"},
		{"/api/v1", "/api/v1", "//other.example/login", "//other.example/login"},
		{"/", "/assets/a", "/login", "/login"},
		{"/café", "/caf%C3%A9/%69tems", "?q=%2b", "/caf%C3%A9/%69tems?q=%2b"},
	} {
		t.Run(tc.uri+"->"+tc.location, func(t *testing.T) {
			response := &http.Response{Header: http.Header{"Location": {tc.location}}}
			must(t, rewriteMountResponse(tc.prefix, tc.uri, response))
			if got := response.Header.Get("Location"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	for _, location := range []string{"", "///other/path", "https://[broken", "https:/missing-host", "https://example.test/%0d", "/ok?bad=%0a", "/ok#bad%0d", "javascript:alert(1)", "data:text/plain,hi", "/bad%", "/bad\\path", "/bad\r\nInjected: yes", "/bad path", "/%2fother", "/%5cother", "/%0d%0a", "/%2e%2e/escape"} {
		t.Run("reject:"+location, func(t *testing.T) {
			response := &http.Response{Header: http.Header{"Location": {location}, "Set-Cookie": {"a=b; Path=/"}}}
			before := response.Header.Clone()
			if rewriteMountResponse("/api", "/api/items", response) == nil {
				t.Fatal("unsafe Location accepted")
			}
			if !reflect.DeepEqual(before, response.Header) {
				t.Fatal("headers changed before rejection")
			}
		})
	}
	response := &http.Response{Header: http.Header{"Location": {"/one", "/two"}}}
	if rewriteMountResponse("/api", "/api", response) == nil {
		t.Fatal("ambiguous Location accepted")
	}
}

func TestMountCookiesPreserveAttributes(t *testing.T) {
	cookies := []string{
		"sid=x; Path=/; Secure; HttpOnly; SameSite=Lax; Custom=value",
		"deleted=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; path=/session; Domain=example.test",
		"__Host-session=x; Path=/; Secure",
		"noPath=x; Secure", "relative=x; Path=relative", "two=x; Path=/; Path=/child", "spaced=x; Path= /  ; Secure",
	}
	want := []string{
		"sid=x; Path=/api/v1; Secure; HttpOnly; SameSite=Lax; Custom=value",
		"deleted=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; path=/api/v1/session; Domain=example.test",
		cookies[2], cookies[3], cookies[4], "two=x; Path=/api/v1; Path=/api/v1/child", "spaced=x; Path= /api/v1  ; Secure",
	}
	response := &http.Response{Header: http.Header{"Set-Cookie": cookies, "Link": {"</asset>"}, "Refresh": {"0; url=/login"}}}
	must(t, rewriteMountResponse("/api/v1", "/api/v1", response))
	if !reflect.DeepEqual(response.Header.Values("Set-Cookie"), want) {
		t.Fatal(response.Header)
	}
	if response.Header.Get("Link") != "</asset>" || response.Header.Get("Refresh") != "0; url=/login" {
		t.Fatal("unrelated headers changed")
	}
	must(t, rewriteMountResponse("/", "/", response))
	if !reflect.DeepEqual(response.Header.Values("Set-Cookie"), want) {
		t.Fatal("root changed cookie paths")
	}
}

func TestListenerMountResponseRewriting(t *testing.T) {
	for _, mode := range []string{"preserve", "strip", "strip-disabled"} {
		enabled := mode == "strip"
		for _, unsafe := range []bool{false, true} {
			t.Run(strings.Join([]string{mode, map[bool]string{true: "unsafe", false: "redirect"}[unsafe]}, "/"), func(t *testing.T) {
				f := testFixture(t)
				if mode != "preserve" {
					routes, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{targetID: {AllowedPaths: []string{"/api"}, Rollout: registry.Rollout{Stable: "v1"}}}})
					must(t, err)
					reg := v1.Register{Type: "register", ProtocolVersion: 1, Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities(), ServiceID: targetID, InstanceID: "target-1", Version: "v1", Paths: []string{"/api"}, PathMode: "strip", RewriteMountHeaders: enabled, MaxConcurrentRequests: 4}
					registered, err := routes.RegisterAuthorized(reg, registry.QUIC)
					must(t, err)
					_, err = routes.BindTransport(registered.Session, reg, registry.QUIC)
					must(t, err)
					must(t, routes.SetReady(registered.Session, true))
					must(t, routes.ActivateAuthorized(targetID, "/api", routes.Revision()))
					f.selected, f.config.Routes = registered.Session, routes
				}
				location := "/login?x=%2b#f"
				if unsafe {
					location = "javascript:alert(1)"
				}
				f.config.Resolve = func(_ctx context.Context, _ registry.Decision) (Recipient, error) {
					return Recipient{Key: f.recipient, Transport: transport{handle: f.selected, send: func(req *http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: 302, Header: http.Header{"Location": {location}, "Set-Cookie": {"session=x; Path=/; HttpOnly"}}, Body: io.NopCloser(strings.NewReader("unchanged body"))}, nil
					}}}, nil
				}
				configured, err := NewServer(f.config)
				must(t, err)
				address, client := runServer(t, configured, f.clientTLS)
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				status := 302
				if enabled && unsafe {
					status = 502
				}
				response := send(t, client, signedRequest(t, address, publicURI, callerID, 0, f.call), status)
				if status == 502 {
					if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
						t.Fatal("unsafe response leaked headers")
					}
					return
				}
				wantLocation, wantCookie := location, "session=x; Path=/; HttpOnly"
				if enabled {
					wantLocation, wantCookie = "/api/login?x=%2b#f", "session=x; Path=/api; HttpOnly"
				}
				body, err := io.ReadAll(response.Body)
				must(t, err)
				if response.Header.Get("Location") != wantLocation || response.Header.Get("Set-Cookie") != wantCookie || string(body) != "unchanged body" {
					t.Fatal("incorrect relayed response", response.Header, string(body))
				}
			})
		}
	}
}
