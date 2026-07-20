# guard — provenance-bound approval

The defensive companion to [Urd](../README.md), kept deliberately separate.

Urd is offensive: it finds where a low-trust MCP server can reach a high-trust
tool, and proves an injection landed. `guard` is the one control that stops it —
a provenance-bound approval gate that blocks a privileged operation when the
target was selected by a low-trust source and the approval surface omitted that
origin.

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
