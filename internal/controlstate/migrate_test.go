package controlstate

import (
	"errors"
	"testing"

	"github.com/solodyagin/outgate/internal/registry"
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
 DROP TABLE registry_snapshot;
 DROP INDEX security_results_action;
 DROP TABLE registration_generations;
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

func TestUpgradeV3PreservesGenerationFenceAndRequiresRegistryBootstrap(t *testing.T) {
	c := securityConfig(t)
	s := fixture(t, c)
	issued, peer, reg := registrationGrant(t, s, 7, "reports-1")
	lease, err := s.AcquireRegistration(t.Context(), issued.DeploymentGrant, peer, reg)
	must(t, err)
	lease.Release()
	_, err = s.ReplaceAccess(t.Context(), registrationChange(t, s), accessRules())
	must(t, err)
	revision, err := s.Revision(t.Context())
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), `BEGIN IMMEDIATE;
 DROP TABLE registry_snapshot;
 DROP INDEX security_results_action;
 ALTER TABLE control_metadata RENAME TO metadata_v4;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=3),epoch BLOB NOT NULL CHECK(length(epoch)=32),revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,3,epoch,revision FROM metadata_v4;
 DROP TABLE metadata_v4;
 COMMIT;`)
	must(t, err)
	must(t, s.Close())
	if old, err := Open(t.Context(), c); err == nil {
		old.Close()
		t.Fatal("implicitly migrated v3")
	}
	must(t, Upgrade(t.Context(), c))
	must(t, Upgrade(t.Context(), c))
	if old, err := openVersion(t.Context(), c, 3); err == nil {
		old.Close()
		t.Fatal("v3 reader accepted v4")
	}
	current, err := Open(t.Context(), c)
	must(t, err)
	defer current.Close()
	assertRevision(t, current, revision)
	_, err = current.VerifyDeploymentGrant(t.Context(), issued.DeploymentGrant, peer, reg)
	must(t, err)
	_, err = current.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/items", false)
	must(t, err)
	var generation, grantID string
	must(t, current.db.QueryRowContext(t.Context(), "SELECT generation,grant_id FROM registration_generations WHERE instance_id=?", reg.InstanceID).Scan(&generation, &grantID))
	if generation != "7" || grantID != issued.Record.GrantID {
		t.Fatal("migration lost generation fence")
	}
	// Migration does not invent route ownership that old schemas never stored.
	cfg := registry.Config{FrontendService: c.RootFrontend, Services: make(map[string]registry.ServiceConfig)}
	for id, paths := range c.Services {
		cfg.Services[id] = registry.ServiceConfig{AllowedPaths: paths, Rollout: registry.Rollout{Stable: "v1"}}
	}
	_, err = current.LoadRegistry(t.Context(), cfg, revision)
	if !errors.Is(err, ErrRegistryUninitialized) {
		t.Fatal("migration enabled empty registry", err)
	}
	events, err := current.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 3 {
		t.Fatal("migration lost operation/outbox")
	}
}

func TestFailedV3UpgradeRollsBackRegistryAddition(t *testing.T) {
	// A real v3 layout with a conflicting partial v4 table must remain v3.
	c := securityConfig(t)
	s := fixture(t, c)
	_, err := s.db.ExecContext(t.Context(), `BEGIN IMMEDIATE;
 DROP TABLE registry_snapshot;
 DROP INDEX security_results_action;
 ALTER TABLE control_metadata RENAME TO metadata_v4;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=3),epoch BLOB NOT NULL CHECK(length(epoch)=32),revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,3,epoch,revision FROM metadata_v4;
 DROP TABLE metadata_v4;
 CREATE TABLE registry_snapshot(existing INTEGER);
 COMMIT;`)
	must(t, err)
	must(t, s.Close())
	if err := Upgrade(t.Context(), c); !errors.Is(err, ErrUnavailable) {
		t.Fatal("partial schema accepted", err)
	}
	old, err := openVersion(t.Context(), c, 3)
	must(t, err)
	defer old.Close()
	assertRevision(t, old, 1)
	var count int
	must(t, old.db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE name='security_results_action'").Scan(&count))
	if count != 0 {
		t.Fatal("failed migration left an index")
	}
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

func TestUpgradeV2PreservesGrantsAndPolicies(t *testing.T) {
	config := securityConfig(t)
	s := fixture(t, config)
	issued, p, reg := registrationGrant(t, s, 7, "reports-1")
	_, err := s.ReplaceAccess(t.Context(), registrationChange(t, s), accessRules())
	must(t, err)
	revision, err := s.Revision(t.Context())
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), `BEGIN IMMEDIATE;
 DROP TABLE registry_snapshot;
 DROP INDEX security_results_action;
 DROP TABLE registration_generations;
 ALTER TABLE control_metadata RENAME TO metadata_v3;
 CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=2),epoch BLOB NOT NULL CHECK(length(epoch)=32),revision TEXT NOT NULL) STRICT;
 INSERT INTO control_metadata SELECT id,2,epoch,revision FROM metadata_v3;
 DROP TABLE metadata_v3;
 COMMIT;`)
	must(t, err)
	must(t, s.Close())
	if _, err := Open(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Open implicitly migrated v2", err)
	}
	must(t, Upgrade(t.Context(), config))
	if old, err := openVersion(t.Context(), config, 2); err == nil {
		_ = old.Close()
		t.Fatal("v2 binary opened v3 state")
	}
	upgraded, err := Open(t.Context(), config)
	must(t, err)
	defer upgraded.Close()
	assertRevision(t, upgraded, revision)
	_, err = upgraded.VerifyDeploymentGrant(t.Context(), issued.DeploymentGrant, p, reg)
	must(t, err)
	_, err = upgraded.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/items", false)
	must(t, err)
	lease, err := upgraded.AcquireRegistration(t.Context(), issued.DeploymentGrant, p, reg)
	must(t, err)
	lease.Release()
}
