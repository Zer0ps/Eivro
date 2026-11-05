# Linux FakeIP allocation patch

Base: official sing-box v1.14.4, commit
`c005f35300ce76427dc285481ec5695f5b179cd2`.
Output version: `1.14.4-eivro.2`. Native Linux x86_64 is the currently verified build.
macOS/Windows continue using their pinned official binaries.

`source.json` pins the upstream source archive, Go toolchain, build tags and patch
SHA-256. `scripts/build-core.py` verifies these inputs, applies the patch to a fresh
source directory, runs the affected Go tests and builds without local VCS metadata.
The default output is a candidate in `work/fakeip-core`; `--output vendor/sing-box`
selects the core used by Linux packaging. Nothing is installed on the host.

The patch changes two production files, adds two production files and three test files:

- Read the retained allocation cursor without deleting it. Missing or invalid
  metadata in a nonempty store, or changed address ranges, must fail startup.
- Reserve the next address synchronously before storing/returning its mapping.
  A failed write does not return an unrecorded address.
- Reject exhausted IPv4/IPv6 pools instead of reassigning existing addresses.
- Use immediate transactions for the serialized allocation path; batching each
  write separately imposed unnecessary delays on DNS replies.
- Add a Linux-only hidden `eivro-retire-fakeip SOURCE_FD TARGET_FD` operation.
  It reads a stopped core's database without changing it, validates allocation
  metadata against retained forward/reverse addresses and writes only that metadata
  into a fresh empty database. The helper supplies inherited FDs, bounds execution
  and atomically publishes the new generation. In-place bucket deletion would leave
  domain strings in unused pages and is deliberately not used for privacy cleanup.

Regression tests cover storage failures, concurrent allocation of one name,
metadata reads and exhausted ranges. `tests/fakeip_core.py` additionally exercises
actual process crashes, restarts, retirement and exhausted-pool preservation.
Retirement tests also check truncated, missing and rewound cursors, unchanged source
bytes and absence of domain strings in the fresh file. `--expect-bugs` permits reproducing the cursor
and wraparound defects against an unmodified v1.14.4 binary. All fixtures use
synthetic names; no traffic logs are enabled.

When updating upstream, re-evaluate this patch against the pinned source and run
the runtime regressions. Remove it only when the upstream implementation passes
the same identity, crash, storage-failure and exhaustion checks. A successful patch
application alone is insufficient. This patch does not claim to fix arbitrary
database corruption or persistent DNS caches in third-party applications.

Upstream licensing remains applicable (`vendor/LICENSE`, shipped as
`sing-box.LICENSE`). The source archive and this patch identify the changes;
public binary distribution must also provide the corresponding source and notices
required by that license.
