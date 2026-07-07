# railcall-contrib

The outside-builder workspace for **RailCall** — local-first automation. *Agents draft. You approve. Receipts prove.*

**Start with [`SCOPE.md`](SCOPE.md)** — it's the one rule that keeps this working: you build against a documented contract, never the sealed engine.

## What's here
- `cli/railcall_cli.py` — the public RailCall CLI (the same one users install)
- `install.sh` — the public installer
- `RECEIPT_FORMATS.md` — the signed-receipt contract every tool must honor
- `qa/` — the QA harness (`bash qa/run.sh`) + attack PoCs
- `discord-bot/` — the Verified-Builder bot (spec + stub)
- `vault/` — the at-rest key-vault interface (spec)
- `FIRST_TASKS.md` — your first three deliverables with acceptance criteria
- `CONTRIBUTING.md` — how to work here

## Not here (by design)
The compose/audit engine, the block library, the hosted gateway, provider identity, and any keys. You don't need them — receipts verify **offline against a public key**. See `SCOPE.md`.

## Quick start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash qa/run.sh          # should pass clean
```
