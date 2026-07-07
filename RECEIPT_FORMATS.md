# RailCall Receipt Formats (public contract)

Every RailCall receipt is **Ed25519-signed** and **verifiable offline**. The signature always covers the receipt's integrity field as a **raw UTF-8 string**, checked against the install's pinned `signing_pubkey.json` (`{public_key_hex, key_id}`). A verifier never needs the engine — only the public key.

There are four shapes in the wild. Any tool you build (verifier, Discord bot, QA harness) must handle all four.

| # | Source | Integrity field | Signature location |
|---|---|---|---|
| 1 | CLI audit receipt | *(flat)* — top-level `integrity` body | top-level `signature_hex` + `public_key_hex` (signs the canonical body) |
| 2 | Studio **build** receipt | `integrity_hash` | nested `signature: {alg, sig, key_id}` |
| 3 | Studio **run** receipt (`railcall_composed_dryrun.v0`, `railcall_sheet_send.v0`) | `integrity` (`"sha256:…"`) | nested `signature: {alg, sig, key_id}` |
| 4 | Workflow **build** receipt (`railcall_workflow_receipt.v1`) | `integrity_root` (`"sha256:…"`) | nested `signature: {alg, sig, key_id}` |

**Verify rule (formats 2–4):** take the first present of `integrity_hash` / `integrity` / `integrity_root`, `str()` it, UTF-8 encode, and verify `signature.sig` against the pinned pubkey whose `key_id` matches. If `key_id` differs from the local install, that's a receipt from a **different install** — report that honestly (it is NOT "unsigned" and NOT "invalid").

**Trust rule (critical, from a real security finding):** load the verifying pubkey **only** from trusted local install paths (`~/.railcall/station/.railcall_workspace`, `~/.railcall/.railcall_workspace`, `RAILCALL_WS`). **Never** load a `signing_pubkey.json` that sits next to the receipt being verified — that lets a forged receipt ship its own key and self-attest. A third-party auditor who wants to trust an external key must pass it **explicitly** (`--key <path>`), which the output then attributes as a user-supplied key.

## Minimal example (format 4)

```json
{
  "schema": "railcall_workflow_receipt.v1",
  "workflow_id": "scheduled_qa_workflow",
  "integrity_root": "sha256:fa85…",
  "artifact": "scheduled_qa_workflow.html",
  "spec": { "name": "...", "steps": [...] },
  "honest_status": "SPEC_VISUAL_RECEIPT",
  "signature": { "alg": "ed25519", "sig": "7704…", "key_id": "84838ed273be6df1" }
}
```
