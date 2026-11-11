# Private filesystem destinations

This recipe prevents nginx/Angie static serving from reading explicitly private
files, even when an innocuous URL, `root`, `alias`, rewrite, internal redirect,
symlink or hardlink selects them. The kernel checks the worker's credentials
when nginx opens the file. No URI classifier, duplicate `stat`, pathname
precheck, Shield directive or native extension is needed.

## Deployment contract

Use this recipe only when all these conditions hold:

- Linux local filesystems enforce normal discretionary access control (DAC).
  The HTTP workers run as a dedicated unprivileged account such as `www-data`;
  they have no DAC-bypass capabilities or privileged serving module. A root
  master uses `user www-data www-data;` in the main context. A nonroot master
  already has the intended worker identity; the `user` directive cannot switch it.
- Explicitly enumerate the private files and trees. A separate trusted account
  owns them. Private files have mode `0600`, private directories `0700`, and
  workers cannot read files or search directories via their owner, any group,
  supplemental groups, ACLs, alternate mounts or another accessible copy.
  Files outside a private tree still need private file permissions. Directory
  permissions alone do not protect hardlinks published outside that directory;
  file permissions protect the same inode through every hardlink.
- Trusted configuration and filesystem writers maintain that partition. The
  backend may read private data under its separate account. It must create new
  private files with restrictive permissions from the start, for example using
  umask `077`, and preserve them during replacement. An untrusted actor cannot
  change owners, modes, ACLs, mounts, or publish readable private copies.
- Every legitimate static response uses a worker-readable public file through
  searchable public directories. Public aliases and symlinks, including mixed
  trusted owners and targets outside the document root, are legitimate.
  The private set has no legitimate static responses. Private application data
  can still be consumed by a separate backend; application response filtering,
  FastCGI execution and arbitrary third-party file-serving modules are outside
  this static-serving contract.

A deployment owner must establish this contract before enabling the recipe.
No supplied command applies host or application changes. For a site with
`/srv/site/public` and `/srv/site/private`, the intended ownership is a trusted
publisher and worker-readable modes for public data, and a separate backend
owner with `0700` directories and `0600` files for private data. Do not recursively
change permissions on a live application's tree without checking its needs.

## nginx configuration

After establishing ownership and permissions, include `serving.conf` at the
`http` or server level and retain its settings in every local-file serving
location. Audit child overrides. Example adaptations (replace paths yourself):

```nginx
# Main context, for a root master:
user www-data www-data;

# Inside http {}:
server {
    listen 8080;
    root /srv/site/public;
    include /etc/nginx/private-destinations/serving.conf;

    location / { }
    location /assets/ { alias /srv/site/shared-public/; }
}
```

`open_file_cache off` avoids retaining file descriptors across requests. Deploy
permissions before any request is served. When withdrawing previously public
access, stop all old workers and close existing requests/descriptors before
starting under the new contract: changing a mode cannot revoke an already-open
file descriptor. A reload alone can leave old workers and in-flight responses.
This recipe is a steady-state access boundary, not an instantaneous revocation
protocol.

`disable_symlinks off` preserves legitimate public symlinks. Kernel permissions
still apply to their final targets. `disable_symlinks on` rejects all symlinks;
`if_not_owner` rejects links whose owner differs from their target. Neither
classifies private data: same-owner links to readable private data can pass
`if_not_owner`, and both settings can reject legitimate public routes. Do not
use either as a substitute for destination permissions or silently add them
to this contract. Native support also depends on the platform; the test matrix
exercises Linux. See nginx's [symlink directive documentation](https://nginx.org/en/docs/http/ngx_http_core_module.html#disable_symlinks)
and [worker user documentation](https://nginx.org/en/docs/ngx_core_module.html#user).

The preservation argument covers the declared route classes: `root`, `alias`,
rewrites, named/error/internal redirects and symlinks eventually open a file
with the same worker credentials. Every declared public file remains readable,
regardless of its URL or owner; every private inode remains unreadable. There
is no additional pattern-based rejection. This argument depends on the contract,
not on opt-in or a finite test count, and does not certify arbitrary deployments.

## Verification

Run the focused fixture as root **only inside a disposable container** so it can
assign distinct worker/file identities; it refuses an unprivileged run. It
creates and changes permissions only under its own temporary directory and
starts workers as `www-data`. It never loads Shield or executes a backend.

```sh
python3 ci/tests/test_private_destinations.py \
    --nginx /path/to/nginx --output /tmp/private-destinations -v
```

CI runs the same fixture against the supported nginx and Angie debug matrix.
Responses are matched against unique public/private byte sentinels and recorded
with the fixture paths, device/inode identities and SHA256 values. Cases include
direct and disguised aliases, rewrites, URI/named/error redirects, final and
intermediate symlinks, hardlinks, range/HEAD, missing files and malformed URLs.
The suite also removes DAC restrictions in a separate fixture and requires the
same private routes to return the exact private bytes. Native symlink policy
comparisons show legitimate mixed-owner public links and same-owner readable
private links explicitly.

For an observable red control, run with `--disable-permissions -k test_private`:
the ordinary protection assertions must fail because the private bytes leak.
Omit the option to restore the passing candidate. `--wrong-public-oracle` makes
`test_public` fail on an intentionally wrong expected identity. Neither option
is enabled in the normal suite. Configuration and response evidence are retained
under `--output` in a fresh `run-*/fixtures` archive for every invocation, so
repeating the command preserves earlier evidence and the actual test verdict.
No blanket status-only success claim is made.
