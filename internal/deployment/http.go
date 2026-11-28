package deployment

import (
	"encoding/json"
	"time"

	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/servicecall"
)

// BindHTTPPolicy fills signed-ingress request deadlines and the shared request
// rate ceiling. It does not configure browser/WebSocket/body-size/session limits.
func BindHTTPPolicy(doc *config.Document, base gateway.Config) (gateway.Config, error) {
	if doc == nil || doc.Mode() != "production" || base.Service.HTTP != (servicecall.HTTPPolicy{}) || base.Service.GlobalRate != (servicecall.GlobalRate{}) {
		return gateway.Config{}, ErrProfile
	}
	values := doc.Values()
	if len(values) == 0 {
		return gateway.Config{}, ErrProfile
	}
	var in struct {
		Routing struct {
			Header  string `json:"response_header_timeout"`
			Idle    string `json:"body_idle_timeout"`
			Request string `json:"request_timeout"`
		}
		Security struct {
			Rates struct {
				RPS   int `json:"signed_per_second"`
				Burst int `json:"signed_burst"`
			} `json:"rate_limits"`
		}
	}
	in.Routing.Header = "60s"
	in.Routing.Idle = "60s"
	in.Routing.Request = "0s"
	in.Security.Rates.RPS = 1000
	in.Security.Rates.Burst = 2000
	data, err := json.Marshal(values)
	if err != nil {
		return gateway.Config{}, ErrProfile
	}
	defer clear(data)
	if err := json.Unmarshal(data, &in); err != nil {
		return gateway.Config{}, ErrProfile
	}
	header, err := time.ParseDuration(in.Routing.Header)
	if err != nil || header <= 0 {
		return gateway.Config{}, ErrProfile
	}
	idle, err := time.ParseDuration(in.Routing.Idle)
	if err != nil || idle <= 0 {
		return gateway.Config{}, ErrProfile
	}
	request, err := time.ParseDuration(in.Routing.Request)
	if err != nil || request < 0 {
		return gateway.Config{}, ErrProfile
	}
	if in.Security.Rates.RPS < 1 || in.Security.Rates.Burst < 1 {
		return gateway.Config{}, ErrProfile
	}
	base.Service.HTTP = servicecall.HTTPPolicy{ResponseHeaderTimeout: header, BodyIdleTimeout: idle, RequestTimeout: request}
	base.Service.GlobalRate = servicecall.GlobalRate{PerSecond: in.Security.Rates.RPS, Burst: in.Security.Rates.Burst}
	return base, nil
}
