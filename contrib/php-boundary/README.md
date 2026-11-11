# Native PHP execution boundary

This opt-in nginx/Angie recipe sends only declared absolute script filenames to
FastCGI. The example runs `/srv/shield-site/app/index.php` and
`/srv/shield-site/app/health.php`. The filesystem trees
`/srv/shield-site/uploads`, `/srv/shield-site/cache`, and
`/srv/shield-site/media` are non-executable through this integration, whatever
URL would otherwise map to them. Public uploads and media remain readable.
It needs the standard HTTP map, rewrite, try-files and FastCGI modules; it has
no dependency on Shield's scanner or its mode.

## Site contract

Adapt this example only when all these conditions describe the site:

- Linux uses a case-sensitive filesystem. The approved scripts are existing
  regular files at their declared absolute paths. The application and every
  parent of those paths are trusted, cannot be renamed or modified by upload
  users, and have no symlink, hardlink, bind-mount or backend path mapping that
  aliases an approved script to a non-executable tree. Keep that invariant
  during deployments too. This recipe does not resolve filesystem identities.
- The backend executes the exact `SCRIPT_FILENAME` it receives. Its filesystem
  namespace agrees with the declared paths. Applications can still read data
  or include files themselves; this protects nginx's script dispatch, not PHP
  application code, backend configuration or code execution inside an entrypoint.
- Approved URI paths are case-sensitive: `/index.php` and `/health.php`.
  `/index.php/anything` is supported PATH_INFO, including `/` and suffixes with
  `.php`; `/health.php/anything` is not a route. nginx's normalized current URI
  drives selection. Percent escapes are decoded once by nginx, never again by
  this recipe. Query strings and request bodies do not select a script.
  Exact routes use PCRE's `\z` end anchor, so a decoded terminal newline cannot
  extend `/index.php` or `/health.php`. The broader PHP location deliberately
  catches these undeclared forms and rejects them before ordinary-route
  fallback. Once `/index.php/` starts PATH_INFO, the complete normalized suffix
  is preserved, including decoded newlines.
- `/` and missing ordinary application routes go to `/index.php`. Existing
  public files are static; public directories use `index.html`. `/uploads/`
  and `/media/` expose public data via aliases; `/cache/` has no public alias.
  A URI ending in `.php` (in any case), or `.php/` plus PATH_INFO, must go
  through the guarded PHP handler and is rejected unless declared. A site
  requiring static downloads with those suffixes needs a separate explicit
  download contract. Public data is assumed safe to publish as bytes; these
  aliases do not promise content confidentiality or safe browser rendering.
- Every FastCGI location in this server, including exact, regex, named, nested,
  internal and error handlers, uses `dispatch.conf` as its complete handler.
  There are no alternative PHP handlers/protocols, inherited FastCGI passes,
  duplicate parameters, `fastcgi_split_path_info`, request-driven script
  overrides or later rewrites after the include. `params.conf` is the complete
  parameter list at that location; do not combine it with `fastcgi_params` or
  `fastcgi.conf`. Local `fastcgi_param` directives replace the inherited list;
  carry all site-required parameters and policies into this file on adaptation.
  Add application-specific parameters there only after review.
- The `shield_php_*` variables belong exclusively to these maps. Do not assign
  them with `set`, use their names for captures, or consume routing maps before
  location rewrites complete. The maps are `volatile` so an internal redirect
  cannot reuse an earlier script decision. This namespace and this route table
  are for one site; use separate namespaces when adapting multiple sites in
  one HTTP context.

These are configuration and deployment obligations, not claims that arbitrary
applications are safe. A hostile alternative handler can bypass any include.
`nginx -t` catches missing map variables and incorrect include contexts, but
cannot prove path ownership, backend semantics, allowlist correctness or that
all handlers use this recipe. Inspect the complete effective configuration.

## Install and adapt

Copy the four `.conf` files to `/etc/nginx/shield-php-boundary/`. Replace every
`/srv/shield-site` consistently with a trusted absolute site path; nginx regex
metacharacters in paths must be escaped in `maps.conf`. The sample path uses
only regex-safe characters. Keep the approved scripts outside every nonexec
subtree and keep the explicit `(?:/|$)` directory boundaries. These filesystem
regexes are case-sensitive; do not change them to `~*` on Linux. nginx literal
map keys ignore case, which is why the sample uses anchored `~` regex keys.

Declare the maps once in `http {}` and define the backend there:

```nginx
http {
    include /etc/nginx/shield-php-boundary/maps.conf;
    upstream shield_php_backend {
        server unix:/run/php/site-fpm.sock;
    }
    server {
        listen 8080;
        server_name example.test;
        include /etc/nginx/shield-php-boundary/server.conf;
    }
}
```

Replace the example site's existing PHP/routing handlers with the adapted
`server.conf`; do not append it alongside a generic PHP handler. Set the real
listen address, name and FPM endpoint in your site configuration. Keep unrelated
TLS, logging and Shield directives appropriate for the site. No supplied
command installs or reloads configuration automatically.

To add an entrypoint, add an anchored URI rule to each relevant routing map
(`shield_php_script`, `shield_php_name`, and optionally `shield_php_path_info`)
and its exact absolute script to `shield_php_allowed`. Keep the nonexec map
independent: a script accidentally allowed under an excluded tree still returns
403. Do not derive an approved script from `$document_root`, `$request_filename`,
`$fastcgi_script_name`, a header, a query parameter or a regex capture. The
shipped script selection values are constants.

For a legitimate named fallback, rewrite to an approved URI and restart location
selection:

```nginx
location @site_front {
    rewrite ^ /index.php last;
}
```

For a legitimate error fallback that retains the query string:

```nginx
error_page 404 = /index.php$is_args$args;
```

Apply such fallbacks only to the intended application locations. Globally
mapping rejected uploads to the front controller changes rejection behavior.
A named FastCGI handler that retains an unapproved URI must reject it; including
`dispatch.conf` does not silently turn that URI into an approved entrypoint.

Request headers retain nginx's normal FastCGI forwarding semantics. For example,
a client `Proxy` header becomes `HTTP_PROXY`. This script boundary does not
impose an httpoxy policy or remove legitimate application headers. Keep HTTP
clients patched and review existing header policies when replacing a parameter
list. If the site's explicit contract forbids using that header in PHP, carry
its mitigation into the local `params.conf`:

```nginx
fastcgi_param HTTP_PROXY "";
```

nginx then omits `HTTP_PROXY`, including its automatic header-derived value.
This is an optional site policy: applications that
legitimately consume `Proxy` must retain their intended semantics instead. An
inherited empty parameter is not preserved merely by adding this recipe's local
parameter list.

Before deployment run `nginx -t` (or `angie -t`) against the complete adapted
configuration. Inspect `nginx -T` locally for all FastCGI handlers and duplicate
parameter includes; its output can contain secrets, so do not publish it.
Exercise the application's declared routes and upload/media downloads in staging
with a recording backend before switching the backend to PHP.

## Why this boundary holds

The only script string serialized into `SCRIPT_FILENAME` is
`$shield_php_script`. Immediately before the FastCGI content handler, the
location rewrite checks reject that same value when it matches a declared
nonexec tree or fails the independent exact-script allowlist. The parameter list
contains that name once. No rewrite or script reassignment follows the checks.
For every request reaching this handler, the passed string is therefore an
approved constant outside the excluded trees. A root, alias or URL rewrite
cannot create a different script string. Even an accidentally introduced legacy
routing value such as `$request_filename` is rejected unless its final value
passes both checks. This is a string boundary under the filesystem/backend
invariants above, not a URI-prefix filter or a symlink check.

All legitimate requests in the declared contract retain their intended handler:
public data uses the static handler; exact approved routes select their declared
scripts; PATH_INFO is passed separately without altering the script; ordinary
application fallbacks select the front controller. The checks accept each
approved constant and are independent of body, query, ordinary headers and
application data. The nonexec trees cannot contain a legitimate PHP entrypoint
under this contract. This argument covers the route classes; the finite test
matrix below checks that nginx implements the configuration as intended.

The guards use rewrite-module `if` only with `return`. This is not a callback at
the FastCGI wire boundary: its safety relies on the complete-handler contract,
with no later mutable script source or overridden parameters. Arbitrary rewrite
chains, backend retries that change parameters, njs/Lua handlers, application
chroots with different path meanings, case-insensitive filesystems, script
symlinks, generic extension dispatch and automatic application discovery are
outside this recipe. A configuration checker or a final-handoff integration
must establish its own additional contract.

## Reproduce the checks

```sh
python3 ci/tests/test_php_boundary.py --nginx /path/to/nginx --output .build/php-boundary
```

The test loads copies of these files in an isolated prefix and records every
FastCGI parameter pair and STDIN bytes without executing PHP. It checks
entrypoints, POST and
query preservation, PATH_INFO, normalized escapes, URI case, static aliases,
filesystem case, tree boundaries, root/alias generated filenames, rewrite,
named/error redirects, bad encoding and invalid include placement. Test-only
legacy mappings intentionally attempt forbidden filenames through innocuous
URLs. Removing both guards makes those same requests reach the recorder; the
default suite verifies this causal control.

To observe the protection assertion fail with the restriction disabled:

```sh
python3 ci/tests/test_php_boundary.py --nginx /path/to/nginx \
    --disable-guards -k test_final_script
```

That command must exit nonzero with `forbidden backend dispatch`. A separate
body-preservation control injects an inherited `fastcgi_pass_request_body off`:

```sh
python3 ci/tests/test_php_boundary.py --nginx /path/to/nginx \
    --disable-body -k test_post_body
```

This must fail with `FastCGI STDIN differs` for nonempty POST bodies even though
the forwarded `CONTENT_LENGTH` is correct. Empty, short and binary bodies spanning
multiple FastCGI records are covered. Restore normal options and the suite must
pass. CI runs the normal suite against its pinned
nginx and Angie debug builds; no PHP runtime is required.

Reference semantics: [nginx map](https://nginx.org/en/docs/http/ngx_http_map_module.html)
(case matching and volatile variables) and
[FastCGI parameters](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_param)
(parameter inheritance and serialization).
