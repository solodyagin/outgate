package controlstate

import (
	"errors"
	"testing"
)

// This constructs the published v1 layout, not a wire fixture. The old mutation
// fingerprint/result and pending event are created before removing v2 additions.
func legacyDatabase(t *testing.T) (Config, Command, Result) {
	t.Helper()
	config := securityConfig(t)
	s := fixture(t, config)
	c := command(t, Target{Kind: "service", ServiceID: "other"}, 1)
	result, err := s.Revoke(t.Context(), c)
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), `BEGIN IMMEDIATE;
 DROP TABLE security_results;
 DROP TABLE deployment_grants;
 DROP TABLE access_snapshot;
 ALTER TABLE control_metadata RENAME TO metadata_v2;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),epoch BLOB NOT NULL CHECK(length(epoch)=32),revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,1,epoch,revision FROM metadata_v2;
 DROP TABLE metadata_v2;
 COMMIT;`)
	must(t, err)
	must(t, s.Close())
	return config, c, result
}

func TestUpgradePreservesLegacyRevocationsOperationsAndOutbox(t *testing.T) {
	config, c, result := legacyDatabase(t)
	if _, err := Open(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Open implicitly migrated legacy state", err)
	}
	legacy, err := openVersion(t.Context(), config, 1)
	must(t, err)
	if err := Upgrade(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("upgrade bypassed live owner", err)
	}
	must(t, legacy.Close())
	wrong := config
	wrong.Epoch[0]++
	if err := Upgrade(t.Context(), wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatal("upgrade accepted wrong epoch", err)
	}
	must(t, Upgrade(t.Context(), config))
	must(t, Upgrade(t.Context(), config))
	if _, err := openVersion(t.Context(), config, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old binary accepted schema 2", err)
	}
	current, err := Open(t.Context(), config)
	must(t, err)
	defer current.Close()
	assertRevision(t, current, 2)
	repeated, err := current.Revoke(t.Context(), c)
	must(t, err)
	if repeated != result {
		t.Fatal("migration changed committed operation result")
	}
	events, err := current.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 1 || events[0].OperationID != c.OperationID || events[0].Target != c.Target {
		t.Fatal("migration lost pending audit")
	}
	revoked, err := current.IsRevoked(t.Context(), c.Target)
	must(t, err)
	if !revoked {
		t.Fatal("migration lost revocation")
	}
	snapshot, revision, err := current.Access(t.Context())
	must(t, err)
	if revision != 2 || len(snapshot.Policies) != 0 || len(snapshot.InternalOnly) != 0 {
		t.Fatal("migration bootstrapped access allow")
	}
	_, err = current.IssueGrant(t.Context(), change(t, 2), binding())
	must(t, err)
}

func TestFailedUpgradeRollsBackMetadataAndTables(t *testing.T) {
	config, _, _ := legacyDatabase(t)
	legacy, err := openVersion(t.Context(), config, 1)
	must(t, err)
	// A conflicting partial table makes the transactional upgrade fail midway.
	_, err = legacy.db.ExecContext(t.Context(), "CREATE TABLE deployment_grants(existing INTEGER)")
	must(t, err)
	must(t, legacy.Close())
	if err := Upgrade(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid schema upgraded", err)
	}
	legacy, err = openVersion(t.Context(), config, 1)
	must(t, err)
	defer legacy.Close()
	assertRevision(t, legacy, 2)
	var count int
	must(t, legacy.db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE name='access_snapshot'").Scan(&count))
	if count != 0 {
		t.Fatal("failed migration left partial tables")
	}
}
