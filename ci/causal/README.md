# Causal scanner and paired variant gates

Run `python3 ci/causal/check.py --validate` and
`python3 ci/causal/test_check.py` for the cheap fixture gates. The scan unit
runner also runs `check.py --nginx-source CONFIGURED_NGINX --output REPORT`.
The HTTP suite includes `ci/causal/http.t` in debug and sanitizer CI.

`scan.c` includes the real scanner in a test-only translation unit. The build
helper copies the production headers and makes only the two descriptor tables
mutable. Signature bytes, category flags, scanner logic and the nginx decoder
are unchanged. The adapter enumerates compiled entries; the gate requires an
exact match with the shipped ledger census. Stable identities include the kind,
category/rule name and hexadecimal signature/term bytes, rather than a category
hit alone.

Each selected entry is the only enabled predicate. Its positive and reordered
terms must hit the intended category; removing that whole predicate must make
both clean. Every proper AND subset, each term alone and sequential separate
buffers must stay clean. Subset generation is capped at four terms, cases at
64 and input buffers at 4096 bytes. Whole-engine detection is recorded
separately and cannot substitute for an isolated result. The overlapping Java
fixture deliberately still hits `deserial` in the whole engine while proving
the isolated `java_eval` signature. This gate currently covers four standalone
signatures and all six AND rules, **10 of 657 scanner table entries**. Reports
list the other 647 entries explicitly. Structural HTTP checks and exploit
semantics are outside that census; HTTP smoke tests do not prove exact rule
identity.

`variants.json` pins 24 paired workflow rows from two existing SQLite roots
and one explicitly uncertain root (`id=2`). The finite transforms are identity,
percent escaping of form values, form plus encoding, and SQL keyword case.
Python's form parser and the actual in-memory SQLite vulnerable/parameterized
pair must preserve the exact outcomes of each root. Arbitrary mutations,
double decoding, unsupported SQL dialects and other encodings have no presumed
label. Content storage round-trips the same decoded value as inert JSON data;
it never evaluates SQL. The same attack-looking value is benign content and
an attack only at the controlled vulnerable sink. Unknown query outcomes stay
unclassified. Labels are established before scanner observations are consulted.

All descendants retain `sqlite-toy-sink-v1` and `heldout`, including the
uncertain root. The original corpus retains its separate development group,
all 36 historical bindings, and four unclassified historical positives.
Transform, parent hash, label, split, group or count drift fails validation.
The 24 rows are correlated descendants of one toy source group; **there is no
population-validation claim or promotion eligibility**. Duplicate bytes among
benign transforms do not increase the number of independent observations.

The HTTP fixture observes the current module: complete AND gadget detection,
term-alone and cross-buffer negatives, toy SQL variant detection, and benign
acceptance. Its content route explicitly skips `sqli`; 405 from `empty_gif`
means Shield allowed dispatch. That response proves neither storage nor a
vulnerable backend. SQLite outcomes and inert storage are offline evidence;
recording final backend bytes/routes remains the separate HT-17 capability.
The current scanner still matches SQL-looking content without that configured
skip, which remains a reported benign collision rather than an attack label.
