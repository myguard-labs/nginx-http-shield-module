# Offline threat replay

Run `python3 ci/tools/threat-replay.py --validate` for label, fixture and split
checks. The scan-unit runner also compiles the pinned baseline and current
candidate independently against the same configured nginx core. For a retained
JSON comparison, run:

```sh
python3 ci/tools/threat-replay.py --nginx-source /path/to/configured/nginx \
    --output /tmp/shield-replay.json
```

The baseline is commit `189bd9e5f8af78f86cfaa6ae456159d239a1c653`.
The runner reads its scanner/header bytes using `git show`; a missing baseline
fails rather than substituting current sources. Results contain source and
binary hashes. Input uses the production body skip mask and form-only plus
decoding, real automata and nginx decoding functions. CVE profiles, request
routing, HTTP actions and ban accounting are outside this scanner-only replay.

`corpus.json` retains all 36 historical body-corpus rows. Their original roles,
per-body hashes, historical scanner categories and whole-source hash record
provenance. The 32 authored-content cases use a storage-without-evaluation
contract. Four historical positive scanner controls have no evidenced sink;
their derived label is `unclassified`, never attack TP. Source bytes remain in
the local memory evidence path named in the manifest.

The metadata tutorial replaces its original metadata-service address with
documentation address `192.0.2.1`. Its historical `ssrf_meta` observation and
original input hash are preserved, but the sanitized bytes are a different
fixture. A clean sanitized result does not reproduce or refute that original
collision. Both the original and sanitized tutorial currently match
`ssrf_meta`: the retained `/latest/meta-data/` path is itself a shipped marker.
Their distinct body hashes keep those observations separate. Reproduction of
the original is local offline evidence only; its working target is deliberately
absent from this tree.

Two fixtures use a controlled SQLite in-memory database containing public and
private dummy canaries. The sink contract permits selecting a public row by
ID, and forbids selecting the private table. A UNION input returns the private
dummy only from the deliberately vulnerable concatenated query; the same input
returns no row from the parameterized query. This establishes the label only
for this toy sink. Neither query opens files, performs commands or uses a
network. The benign fixture returns the public dummy from both queries.

All historical fixtures share one development source group. The entire toy
SQLite source group is held out, including its benign neighbor. This is a
grouped mechanical split, with only two independent source groups; it is not
independent real-world validation or an estimate of a population false-positive
rate. Label checks run before either scanner, and scanner output never changes
a semantic label. Later causal and backend work owns richer sink/variant
evidence and rule attribution.

The comparison reports TP/FN/FP/TN and unexplained scanner matches by split,
body surface and returned category. It fails on new benign matches or lost
attack matches. Existing benign matches remain visible and make
`promotion_eligible` false; a successful comparison means no regression, not
permission to promote defaults or a zero-false-positive claim. Historical
categories are provenance, not expected labels or a substituted baseline.
