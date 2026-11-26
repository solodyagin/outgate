package servicecall

import (
	"context"
	"net/http"

	"github.com/solodyagin/outgate-sdk/replay"
)

// OpenSQLiteServer opens the provisioned verifier database, then constructs the
// dedicated listener. The caller shuts down the server before closing the store.
func OpenSQLiteServer(ctx context.Context, config Config, storage replay.SQLiteConfig) (*http.Server, *replay.SQLite, error) {
	if config.Replay != nil || config.ReplayNamespace != "" {
		return nil, nil, ErrConfig
	}
	store, err := replay.OpenSQLite(ctx, storage)
	if err != nil {
		return nil, nil, err
	}
	config.Replay, config.ReplayNamespace = store, storage.Namespace
	server, err := NewServer(config)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return server, store, nil
}
