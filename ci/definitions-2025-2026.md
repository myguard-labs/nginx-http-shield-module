# 2025–2026 web application CVE survey

Reviewed 13 November 2026. This is a targeted survey of HTTP-reachable
application/framework issues, prioritizing October 2026 PHP disclosures; it is
not an exhaustive CVE inventory. Shield accepts attack-only byte patterns,
not bans on normal application endpoints or protocol features.

## Added: React2Shell reference gadgets

CVE-2025-55182 affects React Server Components deserialization. Shield carries two
`deserial` signatures: `:__proto__:then` and `:constructor:constructor`.
These match the property-chain suffix regardless of the Flight chunk number.
The first targets prototype access to the chunk's then method; the second
targets the function constructor. Individual keys (`then`, `constructor`,
`__proto__`), ordinary Flight references and near misses remain allowed.

Sources: [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
and [researcher's payload reference](https://github.com/freeqaz/react2shell/blob/master/PAYLOAD_REFERENCE.md).
The fixtures contain inert references without executable commands.

Generic coverage is for these literal gadget families in inspected buffers,
including normal percent decoding and case folding. It is not complete CVE
protection: JSON Unicode escapes are not decoded by the generic scan, body
inspection can be disabled, binary media types are excluded, and only the
configured body prefix is scanned. The separate opt-in `json_escapes` profile
adds one bounded JSON string-escape view for the same two suffixes; it is not a
general Flight decoder.
The gadgets need not appear in every possible exploit. Upgrade React/Next.js.
These additions do not claim coverage for the separate 2026 RSC DoS bugs.

## October PHP: no reliable literal signature

The [PHP October release announcement](https://news-web.php.net/php.announce/513)
identifies fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
Use these fixes or vendor backports, or a subsequent supported fixed release.

- [CVE-2026-109618: OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
  Allocation failure can interrupt partial initialization. Multipart header
  amplification, empty file controls and nested field names are possible
  triggers, but none is an attack-only literal. A small inspected prefix
  cannot bound decoded body size, part/header counts or PHP allocations.
- [CVE-2026-109619: stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
  Exploitation depends on state left by an earlier request and consumed by a
  later one in the same PHP worker. Shield cannot see that worker state.
  Session upload progress is one path, not the entire vulnerability.
- [CVE-2026-115560: session follow-up](https://www.php.net/archive/2026.php).
  PHP's 23 October notice describes a remaining case involving a runtime
  change from `php_binary`/`php_serialize` to `php` plus upload progress.
  Application configuration and runtime state cannot be inferred from a
  fixed request substring. No signature is added for this case either.
- [CVE-2026-111497: Brotli dependency](https://www.php.net/archive/2026.php).
  The 26 October Windows package rebuild fixes a decoder reached through
  cURL's optional response decompression. Shield inspects incoming requests,
  not responses fetched by PHP; an inbound literal cannot cover this path.

Do not block `PHP_SESSION_UPLOAD_PROGRESS`, multipart content types, chunked
requests or nested field syntax globally: they also have legitimate uses and
would not cover all the vulnerable paths. PHP's advisory recommends patching;
configuration changes and request limits only reduce specific exposures.
Shield does not implement multipart structural limits or cross-request PHP
state tracking. Its `shield_max_body` inspection limit is not a request-size
rejection limit.

## Other evaluated candidates

| CVE | Primary source | Disposition |
| --- | --- | --- |
| CVE-2025-29927 | [Next.js middleware authorization bypass](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) | No literal was added. The separate opt-in `nextjs_middleware` profile implements the vendor's header-name workaround for an application-scoped location. Blocking the word `middleware` in arbitrary values would be too broad. |
| CVE-2025-3248 | [Langflow code validation RCE](https://github.com/langflow-ai/langflow/security/advisories/GHSA-rvqx-wpfh-mfx7) | No endpoint ban. `/api/v1/validate/code` is also a legitimate authenticated operation; arbitrary submitted Python has no single mandatory attack-only byte pattern. |
| CVE-2026-33017 | [Langflow public flow build RCE](https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx) | No endpoint ban. Public flow building is a product feature. Exploitability depends on attacker-supplied executable flow data, not the path alone. |
| CVE-2026-21858 | [n8n webhook file access](https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg) | No blanket webhook/form ban. The advisory supplies no attack-only literal; legitimate workflows use these endpoints. |
| CVE-2026-23864 | [React RSC DoS](https://github.com/react/react/security/advisories/GHSA-83fc-fqcc-2hmg) | No signature. The advisory does not establish a mandatory attack-only literal; React2Shell gadget matching does not demonstrate DoS coverage. |
| CVE-2026-23870 | [React RSC DoS](https://github.com/react/react/security/advisories/GHSA-rv78-f8rc-xrxh) | No signature. CPU/memory exhaustion requires protocol/resource controls or an upstream fix; blocking normal Flight reference markers would break applications. |

Existing generic injection signatures may catch individual exploit payloads for
some of these issues. That is not evidence of complete coverage for a CVE.
