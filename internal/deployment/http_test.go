package deployment

import (
	"errors"
	"testing"
	"time"

	configuration "github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/servicecall"
)

func TestHTTPPolicyMapping(t *testing.T) {
	doc, v := fixture(t)
	c, err := BindHTTPPolicy(doc, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Service.HTTP != (servicecall.HTTPPolicy{ResponseHeaderTimeout: time.Minute, BodyIdleTimeout: time.Minute}) || c.Service.GlobalRate != (servicecall.GlobalRate{PerSecond: 1000, Burst: 2000}) {
		t.Fatal("defaults")
	}
	routing := obj(v, "routing")
	routing["response_header_timeout"] = "25ms"
	routing["body_idle_timeout"] = "40ms"
	routing["request_timeout"] = "1s"
	rates := obj(obj(v, "security"), "rate_limits")
	rates["signed_per_second"] = 2
	rates["signed_burst"] = 3
	c, err = BindHTTPPolicy(document(t, v), gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Service.HTTP != (servicecall.HTTPPolicy{ResponseHeaderTimeout: 25 * time.Millisecond, BodyIdleTimeout: 40 * time.Millisecond, RequestTimeout: time.Second}) || c.Service.GlobalRate != (servicecall.GlobalRate{PerSecond: 2, Burst: 3}) {
		t.Fatal("nondefault mapping")
	}
	if _, err := BindHTTPPolicy(doc, c); !errors.Is(err, ErrProfile) {
		t.Fatal("override accepted", err)
	}
	if _, err := BindHTTPPolicy(&configuration.Document{}, gateway.Config{}); !errors.Is(err, ErrProfile) {
		t.Fatal("zero document accepted", err)
	}
	for _, key := range []string{"response_header_timeout", "body_idle_timeout", "request_timeout"} {
		delete(routing, key)
	}
	delete(rates, "signed_per_second")
	delete(rates, "signed_burst")
	c, err = BindHTTPPolicy(document(t, v), gateway.Config{})
	if err != nil || c.Service.HTTP.RequestTimeout != 0 || c.Service.GlobalRate.PerSecond != 1000 {
		t.Fatal("omitted defaults", err)
	}
}
