# External Host Witness Trace Slot

This folder is intentionally not populated with a fake real-host capture.

The live workshop proves the class using the controlled MCP stdio harness. The `examples/external-host/` directory shows the adapter contract with a sample host-shaped trace. A stronger claim requires a captured trace from a real third-party MCP host.

Use this folder only for a real witness capture gathered from an owned, authorized environment.

Required files for a witness artifact:

```text
raw_capture.jsonl
normalized_urd_trace.jsonl
findings.json
notes.md
```

Required notes:

```text
host name / version
capture method
authorization boundary
what was normalized
what was not claimed
whether the value was exact, normalized, encoded, chunked, or paraphrased
```

Do not fabricate this. A fake witness trace would be worse than no witness trace, which is impressive because no witness trace already annoys the back row.
