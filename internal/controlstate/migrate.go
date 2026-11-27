package controlstate

import "context"

const securitySchema = `
CREATE TABLE deployment_grants(id TEXT PRIMARY KEY, secret_hash BLOB NOT NULL CHECK(length(secret_hash)=32), record BLOB NOT NULL CHECK(length(record)<=1048576)) STRICT;
CREATE TABLE access_snapshot(id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL CHECK(length(payload)<=1048576)) STRICT;
INSERT INTO access_snapshot VALUES(1,CAST('{"policies":[],"internal_only":[]}' AS BLOB));
CREATE TABLE security_results(id TEXT PRIMARY KEY REFERENCES control_operations(id), action TEXT NOT NULL, result BLOB NOT NULL CHECK(length(result)<=1048576)) STRICT;
`

// Upgrade explicitly moves provisioned v1 state to v2 under the same owner lock.
// Epoch, revision, revocations, operation fingerprints and pending events survive.
// Open never performs migrations. Old binaries reject the new metadata version.
func Upgrade(ctx context.Context, config Config) error {
	store, err := openVersion(ctx, config, 1)
	if err != nil {
		current, currentErr := Open(ctx, config)
		if currentErr != nil {
			return ErrUnavailable
		}
		return current.Close()
	}
	defer store.Close()
	conn, err := store.connection(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if _, err := store.metadata(ctx, tx); err != nil {
		return err
	}
	migration := `ALTER TABLE control_metadata RENAME TO control_metadata_v1;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=2), epoch BLOB NOT NULL CHECK(length(epoch)=32), revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,2,epoch,revision FROM control_metadata_v1;
 DROP TABLE control_metadata_v1;` + securitySchema
	if _, err := tx.ExecContext(ctx, migration); err != nil {
		return ErrUnavailable
	}
	if err := store.checkFiles(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return store.checkFiles()
}
