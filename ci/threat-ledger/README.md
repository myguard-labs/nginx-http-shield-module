# Threat ledger storage

`ci/threat-ledger.json` is a fixed index of these two data shards. Each shard
contains complete inherited rows and stays below the repository's 512 KiB
file limit. The loader rejects missing, duplicate, reordered or substituted
shard paths, paths escaping the checkout, invalid fields and differing bases.

`ci/threat-ledger.schema.json` describes the **expanded** `{base, entries}`
value returned by `read_ledger`, rather than the storage index. Validation
checks the combined rows for duplicate IDs, references and shipped-entry drift.
All 663 inherited rows retain their IDs, provenance and unreviewed evidence.
The inventory is not verified exploit protection or permission to promote rules.

`python3 ci/tools/threat-ledger.py` validates the complete ledger.
`--seed` writes the deterministic index and shards only when every target is
absent; an existing target prevents any write. Regeneration preserves logical
row values; JSON object key order has no semantic meaning.
