#!/bin/bash
# RailCall contrib QA gate. Green = safe to PR. Run from repo root or anywhere.
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

echo "== 2b. install.sh copies in sync (repo-root vs website-v2/public) =="
# The two install.sh files must be byte-identical: the site serves
# website-v2/public/install.sh and `railcall update` fetches from GitHub
# raw. Drift between them once bit us in a station cut — the SHA pin
# updated in one location but not the other, and existing operators'
# `railcall update` refused the fresh tarball with a scary integrity
# error. This check catches that class of drift before it ships.
if diff -q "$ROOT/install.sh" "$ROOT/website-v2/public/install.sh" >/dev/null 2>&1; then
  echo "  ok"
else
  echo "  FAIL — the two install.sh files have drifted:"
  diff -u "$ROOT/install.sh" "$ROOT/website-v2/public/install.sh" 2>&1 | head -20
  echo "  Fix: cp website-v2/public/install.sh install.sh   (site copy is authoritative)"
  fail=1
fi

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

