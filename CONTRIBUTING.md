# Contributing to RailCall (outside builder guide)

Welcome. This is how you contribute real work to RailCall without ever touching the sealed engine. Read `SCOPE.md` first — it's the one rule that matters.

## Get set up
1. Accept the GitHub invite to `railcall-contrib` (private).
2. `git clone git@github.com:<owner>/railcall-contrib.git && cd railcall-contrib`
3. `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
4. `bash qa/run.sh` — the QA suite should pass on a clean checkout. If it doesn't, that's your first bug report.

## Workflow
- **Branch:** `feat/<short-name>` or `fix/<short-name>` — never commit to `main`.
- **Small PRs.** One deliverable per PR, described in plain English: what, why, how to test.
- **Evidence over assertion.** If your change makes a claim, prove it — a test in `qa/`, and where it fits, a **signed receipt** attached to the PR. We don't merge "trust me."
- **Review:** the founder (Pat) + a reviewer look at every PR. Expect a fast, direct review — we push back honestly, that's the culture.
- **Credit:** every merged fix/feature is credited to you by name.

## Non-negotiables
- No secrets in commits (CI blocks them). No customer data, no real keys, no PII receipts.
- Work against the documented contract (`RECEIPT_FORMATS.md`, the interface stubs). If you need something the contract doesn't expose, **ask** — don't reverse-engineer.
- Local-first / dry-run by default. Nothing sends or deletes without an explicit human approval step.
- Honest status only. No fake-green — a red test that tells the truth beats a green one that lies.

## What "good" looks like here
The best contributors so far found *real, reproducible* things and proved them: a forged-receipt PoC, a PEP-668 install failure with exact repro, a receipt-format mismatch diagnosed to the field. That's the bar. Break it, document it, fix it, prove it.
