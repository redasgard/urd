# External-host trace adapter example

This folder is a credibility artifact, not a universal interceptor.

The live workshop uses the bundled harness because the room needs deterministic execution. This example shows that Urd's analyzer is not married to that host client. If another host can be observed and normalized into Urd's trace schema, the same source -> sink -> impact analysis applies.

Files:

```text
sample_host_trace.jsonl          pseudo external-host events
normalized_to_urd_trace.jsonl    same events normalized into Urd's event schema
findings.json                    Urd analysis of the normalized trace
findings.dot                     DOT graph from the normalized trace
```

Regenerate:

```bash
python3 scripts/normalize_external_host_trace.py \
  examples/external-host/sample_host_trace.jsonl \
  examples/external-host/normalized_to_urd_trace.jsonl

python3 -m urd.cli analyze \
  --manifests lab/manifests \
  --trace examples/external-host/normalized_to_urd_trace.jsonl \
  --output examples/external-host/findings.json \
  --dot examples/external-host/findings.dot
```

Boundary:

```text
This does not claim live support for arbitrary hosts.
It shows the adapter contract:
  external observation -> normalized trace -> Urd analysis.
```
