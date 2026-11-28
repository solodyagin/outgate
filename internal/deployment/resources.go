package deployment

import (
	"encoding/json"

	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/resourcebudget"
)

// BindSharedResources installs one pool for both existing ingress listeners.
// It interprets configured connection/per-IP ceilings conservatively across TCP
// and QUIC together. tcpConnectionBytes is an explicit operator-measured charge;
// it is not inferred from a body limit or advertised as an RSS bound.
// Other listener/process, FD, stream, rate and CPU budgets remain separate work.
func BindSharedResources(doc *config.Document, base gateway.Config, tcpConnectionBytes int64) (gateway.Config, error) {
	if doc == nil || doc.Mode() != "production" || base.Resources != nil || base.TCPConnectionBytes != 0 || base.Connections.Shared != nil || base.Connections.ConnectionBytes != 0 || base.TunnelLimits.Shared != nil || tcpConnectionBytes < 1 || tcpConnectionBytes > 1<<30 {
		return gateway.Config{}, ErrProfile
	}
	values := doc.Values()
	if len(values) == 0 || values["security"] == nil {
		return gateway.Config{}, ErrProfile
	}
	var in struct {
		Security struct {
			Resources struct {
				Connections int   `json:"external_connections"`
				PerIP       int   `json:"connections_per_ip"`
				Bytes       int64 `json:"buffer_bytes_global"`
			} `json:"resource_limits"`
		}
	}
	in.Security.Resources.Connections = 5000
	in.Security.Resources.PerIP = 50
	in.Security.Resources.Bytes = 536870912
	data, err := json.Marshal(values)
	if err != nil {
		return gateway.Config{}, ErrProfile
	}
	defer clear(data)
	if err := json.Unmarshal(data, &in); err != nil {
		return gateway.Config{}, ErrProfile
	}
	limits := in.Security.Resources
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: limits.Connections, ConnectionsPerIP: limits.PerIP, Bytes: limits.Bytes})
	if err != nil || !pool.CanFit(tcpConnectionBytes) {
		return gateway.Config{}, ErrProfile
	}
	base.Resources = pool
	base.TCPConnectionBytes = tcpConnectionBytes
	return base, nil
}
