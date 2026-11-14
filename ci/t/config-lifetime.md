# Full configuration lifetime check

Run `python3 ci/t/run-config-lifetime.py <configured-build-tree> --output <fresh-dir>`.
Add `--valgrind` for unsuppressed Memcheck with all leak kinds treated as errors.
The configured tree must contain its existing object files. The runner preserves
its compiler and linker flags, recompiles the driver and Shield configuration
translation unit, and links the remaining objects without writing the tree.
Use an instrumented tree for ASan/UBSan and keep leak detection enabled.

The driver includes the original upstream `src/core/nginx.c`. Only its `main`
name and the call to `ngx_init_cycle` are renamed. The wrapper calls the real
`ngx_init_cycle` and records which cycle owns the returned configuration. All
configuration parsing, module registration, HTTP location merging, initialization,
shared-memory setup and listener opening remain upstream operations. It accepts
only the runner's `-t -e stderr -p <private-prefix> -c <config>` invocation and
rejects inherited sockets. It never launches a worker or daemon.

This is an explicit ownership driver for the selected configurations, rather
than a replacement for service shutdown or a general nginx embedding API.
It currently requires Linux and allocation-free `strerrordesc_np` initialization.
The fixtures cover valid, normalized, inherited and explicit-off allowlists,
partial malformed lists, mixed `off`, and a late log-opening failure after a
successful parse. Successful configurations own a real stats shared-memory zone,
TCP listener and log descriptor. Rejections must show their expected diagnostic;
an unrelated parse failure does not satisfy a rejection control. Existing direct
allowlist and request tests own address-matching and inheritance behavior checks.

## Ownership contract

The pinned nginx 1.30.6 and 1.31.8 sources establish these boundaries. Angie 1.12.4
is also exercised. Every run hashes the actual headers, included upstream source,
retained objects, candidate source, rebuilt binaries and generated configurations.

- `src/core/nginx.c`, `main`: `-t` returns after `ngx_init_cycle` without releasing
  its successful cycle. This retained full `nginx -t` leak remains recorded in
  the AL8 evidence; this driver supplies a separate complete lifecycle.
- `src/core/ngx_cycle.c`, `ngx_init_cycle`: success releases `conf.temp_pool`
  and the initial bootstrap pool. Configuration parse failures release both new
  pools, leaving the bootstrap pool to the caller. Its `failed` path closes
  opened files and frees newly owned shared memory before destroying new pools.
  The driver frees only the remaining bootstrap pool on rejection.
- `src/os/unix/ngx_process_cycle.c`, `ngx_master_process_exit`: successful exit
  runs module `exit_master` callbacks, closes listeners, then destroys the cycle
  pool. The driver preserves that order and adds explicit release of process-exit
  resources: new shared-memory zones and declared open-file descriptors. It
  admits no old cycles or inherited listeners, so there is no shared ownership
  decision to guess. Each shared-memory page is checked unmapped with `mincore`.
  Log descriptors stay alive through pool cleanup and are closed afterward;
  descriptor count must return to its pre-initialization value.
- `src/core/nginx.c`, `ngx_save_argv`: its separate argv copy belongs to the
  caller's bootstrap lifecycle. The driver releases exactly that copy.
- `src/core/ngx_crc32.c`, `ngx_crc32_table_init`: an optional allocation returns
  an aligned interior pointer and discards its raw base. The exact source is
  compiled into the driver with only its allocation call forwarded through a
  helper that retains that raw base for final release.
- `src/os/unix/ngx_setproctitle.c`, `ngx_init_setproctitle`: Linux allocates one
  process-lifetime buffer and redirects contiguous environment strings into it.
  The exact source uses a separate, equally narrow forwarding helper. The two
  corresponding retained object files are excluded from linking. Neither helper
  wraps a module allocator or inventories process arguments/environment values.
- `src/core/nginx.c`, `ngx_cleanup_environment` and
  `ngx_cleanup_environment_variable`: registered cleanups intentionally retain
  allocations still referenced by `environ`. Exit callbacks see the active
  environment first. Immediately before final pool destruction the driver retires
  its process environment to an empty static vector, allowing the registered
  cleanup handlers to release their own allocations. The process-title buffer
  is freed afterward. The driver cannot resume parsing or launch workers after
  retirement. Cleanups requiring an active environment would require a new
  ownership contract; the selected modules and configurations are the qualified
  scope, not arbitrary third-party modules.

There is no allocation sweep, individual freeing of module data, suppression
file, disabled configuration leak check or ignored leak kind. Memcheck requires
zero live blocks and zero errors. A qualification must add an unmanaged pool in
the actual Shield `shield_allow` handler in a private source copy, rebuild,
observe the full configuration check fail for the attributable leak, restore
the candidate, rebuild, and observe green. A rejection that never reaches the
mutated allocation is not a mutation control.
