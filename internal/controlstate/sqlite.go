package controlstate

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"modernc.org/sqlite"
)

const schema = `
CREATE TABLE control_metadata(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=4), epoch BLOB NOT NULL CHECK(length(epoch)=32), revision TEXT NOT NULL) STRICT;
CREATE TABLE credential_revocations(kind TEXT NOT NULL, service_id TEXT NOT NULL, value TEXT NOT NULL, revision TEXT NOT NULL, revoked_at TEXT NOT NULL, PRIMARY KEY(kind,service_id,value)) STRICT;
CREATE TABLE control_operations(id TEXT PRIMARY KEY, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), revision TEXT NOT NULL, revoked_at TEXT NOT NULL) STRICT;
CREATE TABLE control_outbox(id TEXT PRIMARY KEY REFERENCES control_operations(id), revision TEXT NOT NULL UNIQUE, payload BLOB NOT NULL) STRICT;
CREATE INDEX control_outbox_revision ON control_outbox(length(revision),revision);
`

// Store has one OS-locked owner for this installation. No cached security
// snapshot is returned before commit: reads consult the authoritative database.
type Store struct {
	version        int
	registrationMu sync.Mutex
	registrations  map[string]*RegistrationLease
	mu             sync.RWMutex // owner lock outlives every checked-out connection
	closed         bool
	db             *sql.DB
	owner          *os.File
	config         Config
	files          [3]os.FileInfo // database, WAL, owner lock
	closeErr       error
}

func (c Config) normalized() (Config, error) {
	if c.Path == "" || c.Epoch == [32]byte{} || c.MaxRegistrations < 0 || c.MaxRegistrations > 1000000 || c.MaxOutboxEvents < 0 || c.MaxOutboxBytes < 0 {
		return Config{}, ErrConfig
	}
	if c.MaxRegistrations == 0 {
		c.MaxRegistrations = 1000
	}
	if c.MaxOutboxEvents == 0 {
		c.MaxOutboxEvents = 100000
	}
	if c.MaxOutboxBytes == 0 {
		c.MaxOutboxBytes = 256 << 20
	}
	path, err := filepath.Abs(c.Path)
	if err != nil || strings.HasPrefix(filepath.ToSlash(path), "//") {
		return Config{}, ErrConfig
	}
	c.Path = path
	return normalizeServices(c)
}

func openDB(path string) *sql.DB {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	address := url.URL{Scheme: "file", Path: path}
	address.RawQuery = url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"synchronous(FULL)", "busy_timeout(1000)", "foreign_keys(ON)"}}.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		panic("outgate: SQLite driver missing")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db
}

func fileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	return info, nil
}

func acquireOwner(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	actual, err := file.Stat()
	expected, inspectErr := fileInfo(path)
	if err != nil || inspectErr != nil || !os.SameFile(actual, expected) || lockOwner(file) != nil {
		_ = file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

// Initialize explicitly provisions an empty revision-1 control database.
// It never overwrites an existing installation. Failed files remain for review.
func Initialize(ctx context.Context, config Config) error {
	config, err := config.normalized()
	if err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal", ".owner"} {
		if _, err := os.Lstat(config.Path + suffix); !errors.Is(err, os.ErrNotExist) {
			return ErrUnavailable
		}
	}
	owner, err := acquireOwner(config.Path+".owner", true)
	if err != nil {
		return err
	}
	defer owner.Close()
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return ErrUnavailable
	}
	db := openDB(config.Path)
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return ErrUnavailable
	}
	if err := durable(ctx, conn); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schema+securitySchema+registrationSchema+registrySchema); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_metadata VALUES(1,4,?,'1')", config.Epoch[:]); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Open requires provisioned DB/WAL/owner files, the expected epoch, and schema
// version 4. Missing/corrupt/restored state is never replaced with an empty DB.
func Open(ctx context.Context, config Config) (*Store, error) {
	return openVersion(ctx, config, 4)
}

func openVersion(ctx context.Context, config Config, version int) (*Store, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	owner, err := acquireOwner(config.Path+".owner", false)
	if err != nil {
		return nil, err
	}
	store := &Store{owner: owner, config: config, version: version}
	for i, path := range store.paths() {
		store.files[i], err = fileInfo(path)
		if err != nil {
			_ = owner.Close()
			return nil, ErrUnavailable
		}
	}
	store.db = openDB(config.Path)
	conn, err := store.connection(ctx)
	if err == nil {
		var result string
		err = conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result)
		if err == nil && result != "ok" {
			err = ErrUnavailable
		}
		if err == nil {
			_, err = store.metadata(ctx, conn)
		}
		if err == nil {
			// Prepare all required tables, not just metadata, at startup.
			queries := []string{"SELECT kind,service_id,value,revision,revoked_at FROM credential_revocations LIMIT 0", "SELECT id,fingerprint,revision,revoked_at FROM control_operations LIMIT 0", "SELECT id,revision,payload FROM control_outbox LIMIT 0"}
			if version >= 2 {
				queries = append(queries, "SELECT id,secret_hash,record FROM deployment_grants LIMIT 0", "SELECT id,payload FROM access_snapshot LIMIT 0", "SELECT id,action,result FROM security_results LIMIT 0")
				if version >= 3 {
					queries = append(queries, "SELECT instance_id,service_id,generation,grant_id FROM registration_generations LIMIT 0")
				}
			}
			for _, query := range queries {
				rows, queryErr := conn.QueryContext(ctx, query)
				if queryErr != nil {
					err = queryErr
					break
				}
				if closeErr := rows.Close(); closeErr != nil {
					err = closeErr
					break
				}
			}
		}
		if err == nil && version >= 2 {
			_, err = store.readAccess(ctx, conn)
		}
		if err == nil && version >= 4 {
			revision, metadataErr := store.metadata(ctx, conn)
			err = metadataErr
			if err == nil {
				_, _, err = store.readRegistry(ctx, conn, revision)
			}
		}
		_ = conn.Close()
	}
	if err != nil {
		_ = store.Close()
		return nil, ErrUnavailable
	}
	return store, nil
}

func durable(ctx context.Context, conn *sql.Conn) error {
	var mode string
	var level, foreignKeys int
	if conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" ||
		conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&level) != nil || level != 2 ||
		conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys) != nil || foreignKeys != 1 {
		return ErrUnavailable
	}
	if err := conn.Raw(func(driver any) error {
		control, ok := driver.(sqlite.FileControl)
		if !ok {
			return ErrUnavailable
		}
		_, err := control.FileControlPersistWAL("main", 1)
		return err
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) paths() [3]string {
	return [3]string{s.config.Path, s.config.Path + "-wal", s.config.Path + ".owner"}
}
func (s *Store) checkFiles() error {
	for i, path := range s.paths() {
		info, err := fileInfo(path)
		if err != nil || !os.SameFile(info, s.files[i]) {
			return ErrUnavailable
		}
	}
	return nil
}

type connection struct {
	*sql.Conn
	once    sync.Once
	release func()
}

func (c *connection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (s *Store) connection(ctx context.Context) (*connection, error) {
	s.mu.RLock()
	fail := func(err error) (*connection, error) { s.mu.RUnlock(); return nil, err }
	if s.closed {
		return fail(ErrUnavailable)
	}
	if err := s.checkFiles(); err != nil {
		return fail(err)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fail(ErrUnavailable)
	}
	if err := durable(ctx, conn); err != nil {
		_ = conn.Close()
		return fail(err)
	}
	if err := s.checkFiles(); err != nil {
		_ = conn.Close()
		return fail(err)
	}
	return &connection{Conn: conn, release: s.mu.RUnlock}, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) metadata(ctx context.Context, q queryer) (uint64, error) {
	var version int
	var epoch []byte
	var text string
	if q.QueryRowContext(ctx, "SELECT version,CASE WHEN length(epoch)=32 THEN epoch ELSE NULL END,CASE WHEN length(revision)<=20 THEN revision ELSE NULL END FROM control_metadata WHERE id=1").Scan(&version, &epoch, &text) != nil || version != s.version || subtle.ConstantTimeCompare(epoch, s.config.Epoch[:]) != 1 {
		return 0, ErrUnavailable
	}
	revision, err := strconv.ParseUint(text, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != text {
		return 0, ErrUnavailable
	}
	return revision, nil
}

func (s *Store) Revision(ctx context.Context) (uint64, error) {
	conn, err := s.connection(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	revision, err := s.metadata(ctx, conn)
	if err != nil {
		return 0, err
	}
	if err := s.checkFiles(); err != nil {
		return 0, err
	}
	return revision, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrationMu.Lock()
	active := len(s.registrations) > 0
	s.registrationMu.Unlock()
	if active {
		return ErrInstanceInUse
	}
	if !s.closed {
		s.closed = true
		s.closeErr = errors.Join(s.db.Close(), s.owner.Close())
	}
	return s.closeErr
}
