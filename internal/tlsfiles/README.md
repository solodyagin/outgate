# Startup TLS files

`LoadServer(ctx, certFile, keyFile)` and `LoadRoots(ctx, caFile)` load static
PEM snapshots from deployment-controlled local regular files. They implement a
prerequisite for deployment configuration mapping (ТЗ 3.7, 5.5, 6.5), not a YAML
loader, command, reload mechanism or complete deployment validator.

- Certificate/CA files are limited to 1 MiB before open and during reads; private
  key files to 16 KiB. Server chains contain 1–16 certificates, CA bundles 1–64.
  Descriptor identity and size are checked after open. Special files are rejected
  before open. These checks assume operator-controlled files and OS ACLs; they
  do not sandbox filesystem races or interrupt arbitrary blocked filesystem IO.
- PEM contains only the expected blocks and whitespace: no ignored preamble,
  trailing data, duplicate certificates, PEM headers, encrypted keys or additional
  private keys. Server keys support RSA 2048–8192, ECDSA P-256/P-384/P-521 and
  Ed25519. The standard TLS parser checks the certificate/key match.
- Every certificate must currently be valid and contain no unhandled critical
  extension. Server leaves must permit server authentication and digital signing
  when the corresponding usage extension is present, and must not be CAs.
  Supplied chain certificates must follow issuer order and verify the preceding
  signature. CA bundles require CA basic constraints and certificate-signing usage.
- All file/parser failures return `ErrUnavailable` without paths, file contents
  or underlying parser diagnostics. Context cancellation remains identifiable.
  Private-key input buffers are cleared on return; parsed private keys remain
  owned by the caller and must remain read-only while a runtime uses them.
- Returned `ValidUntil`/CA deadlines are the earliest certificate expiry in the
  snapshot. The caller must enforce these deadlines during runtime operation.
  Files are not re-read and no background goroutines or descriptors are retained.

The loader does not establish server trust, validate configured DNS names,
check revocations or confirm independence of CA/credentials across listeners.
Those checks belong to deployment mapping and the transport/admission boundaries.
Explicit CA files create a fresh pool, with no implicit system-root fallback.
The existing runtime still independently validates TLS configuration; this package
is not wired into it until the deployment loader is implemented.
