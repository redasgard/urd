# guard — provenance-bound approval

The defensive companion to [Urd](../README.md), kept deliberately separate.

Urd is offensive: it finds where a low-trust MCP server can reach a high-trust
tool, and proves an injection landed. `guard` is the control the operator hits
when a target has it deployed — a provenance-bound approval decision that returns
`BLOCK` when the target of a destructive operation was selected by a low-trust
source and the approval surface omitted that origin.

`guard` decides on Urd's *proven* path: it reads a finding and returns the
verdict. In a real deployment you wire that verdict into the approval loop so it
gates before execution; run against a captured trace (as the workshop does) it is
an after-the-fact audit that reaches the same decision. It currently gates the
`delete_records` destructive sink the workshop demonstrates; the same shape
extends to other destructive sinks.

It is not part of the Urd toolkit and imports nothing from it. It reads Urd's
analysis output as data — the JSON that `urd analyze --output` writes — so it can
live in its own repository and ship on its own schedule.

## Use

```bash
urd analyze --manifests lab/manifests --trace session.jsonl --output findings.json
python -m guard.cli --findings findings.json
```

`BLOCK` when a low-trust source selected a protected target for a high-trust
destructive delete without provenance-aware approval; `ALLOW` otherwise. Exit
code is non-zero on `BLOCK` so it can gate a pipeline.

## Split status

This package sits alongside Urd in the DEF CON bundle only so the workshop can
demonstrate "the one wall" without a second checkout. It has no code dependency
on Urd and is ready to graduate to a standalone repository.
