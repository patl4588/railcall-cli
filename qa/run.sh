#!/bin/bash
# RailCall CLI QA gate. Green = safe to PR. Run from repo root or anywhere.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
PY="${PYTHON:-python3}"
fail=0

echo "== 1. Python sources compile =="
if $PY -m py_compile "$ROOT/cli/railcall_cli.py" "$ROOT/railcall_verify_standalone.py" \
        "$ROOT/qa/test_tamper_fuzz.py" "$ROOT/qa/test_e2e_golden_path.py" "$ROOT/qa/test_formula_injection.py" \
        "$ROOT/vault/vault.py" "$ROOT/discord-bot/bot.py" "$ROOT/qa/test_vault.py"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 2. install.sh parses =="
if bash -n "$ROOT/install.sh"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

# NOTE: intra-repo install.sh drift check was removed when the CLI + website
# split into separate repos. Cross-repo drift protection (railcall-cli vs
# railcall-website/public/install.sh vs railcall-core/install.sh) now lives
# as a GitHub Action in railcall-cli (see .github/workflows/, TODO).

echo "== 3. forged-receipt attack (T1 acceptance) =="
if $PY "$ROOT/qa/attacks/forged_receipt_poc.py"; then echo "  ok"; else echo "  FAIL (loophole present — this is T1)"; fail=1; fi

echo "== 4. CLI regression suite =="
# Run by module name from qa/ so it works on Python <3.12 (which can't take a file path).
if ( cd "$ROOT/qa" && $PY -m unittest test_regressions -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 4b. Vault test suite =="
if ( cd "$ROOT/qa" && $PY -m unittest test_vault -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 4c. Formula injection (Bug 13 vectors - now present, expand assertions) =="
if ( cd "$ROOT/qa" && $PY -m unittest test_formula_injection -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 5. tamper-fuzz the standalone verifier (thousands of mutations, none may verify) =="
if ( cd "$ROOT/qa" && $PY -m unittest test_tamper_fuzz -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 6. fresh-install E2E golden path (install -> audit -> receipt -> verify) =="
if ( cd "$ROOT/qa" && $PY -m unittest test_e2e_golden_path -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo
if [ "$fail" = 0 ]; then echo "ALL GREEN"; else echo "SOME CHECKS FAILED (see above)"; fi
exit $fail

