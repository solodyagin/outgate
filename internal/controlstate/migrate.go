package controlstate

import "context"

const securitySchema = `
CREATE TABLE deployment_grants(id TEXT PRIMARY KEY, secret_hash BLOB NOT NULL CHECK(length(secret_hash)=32), record BLOB NOT NULL CHECK(length(record)<=1048576)) STRICT;
CREATE TABLE access_snapshot(id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL CHECK(length(payload)<=1048576)) STRICT;
INSERT INTO access_snapshot VALUES(1,CAST('{"policies":[],"internal_only":[]}' AS BLOB));
CREATE TABLE security_results(id TEXT PRIMARY KEY REFERENCES control_operations(id), action TEXT NOT NULL, result BLOB NOT NULL CHECK(length(result)<=1048576)) STRICT;
`

const registrationSchema = `
CREATE TABLE registration_generations(instance_id TEXT PRIMARY KEY,service_id TEXT NOT NULL,generation TEXT NOT NULL,grant_id TEXT NOT NULL) STRICT;
`

// Upgrade explicitly advances provisioned v1/v2 state to v3 under owner lock.
// Open never migrates implicitly. Network ownership is not restored after restart.
func Upgrade(ctx context.Context, config Config) error {
	var store *Store
	var err error
	for _, version := range []int{1, 2, 3} {
		store, err = openVersion(ctx, config, version)
		if err == nil {
			break
		}
	}
	if err != nil {
		return ErrUnavailable
	}
	defer store.Close()
	if store.version == 3 {
		return nil
	}
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
	migration := `ALTER TABLE control_metadata RENAME TO control_metadata_old;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=3),epoch BLOB NOT NULL CHECK(length(epoch)=32),revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,3,epoch,revision FROM control_metadata_old;
 DROP TABLE control_metadata_old;`
	if store.version == 1 {
		migration += securitySchema
	}
	migration += registrationSchema
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
