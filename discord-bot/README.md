# Discord "Verified Builder" bot (T2)

A bot that turns a signed receipt into a role — proving RailCall's trust model **in public**. Post a receipt in the channel → the bot verifies it **offline** (per `../RECEIPT_FORMATS.md`) → grants a "Verified Builder" role on a valid signature, or **refuses with the exact failed check** on a tampered/forged one.

## Rules
- **Offline verification only** — no engine, no network beyond Discord. All you need is the receipt + the pinned public key(s) you trust (config, not committed).
- **Trust the pinned key, not the receipt.** Never trust a `signing_pubkey.json` a user uploads alongside the receipt (that's the T1 loophole). The bot verifies against keys **you** configured.
- **Honest refusals.** Tampered receipt → say which check failed (bad signature / unknown key_id / malformed). No vague "invalid".
- **No token in the repo.** `DISCORD_BOT_TOKEN` and the trusted key list come from env only.

## Acceptance
- Post a real signed receipt (any of the 4 formats) → role granted, reply names the signer key_id.
- Byte-flip one field → refused, reply names the failed check.
- Receipt signed by an unpinned key → refused as "unknown signer", not granted.

`bot_stub.py` is the skeleton — it wires the event loop and calls a `verify_receipt()` you implement against the contract.
