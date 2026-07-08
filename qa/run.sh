#!/bin/bash
# RailCall contrib QA gate. Green = safe to PR. Run from repo root or anywhere.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
PY="${PYTHON:-python3}"
fail=0

echo "== 1. CLI compiles =="
if $PY -m py_compile "$ROOT/cli/railcall_cli.py"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 2. install.sh parses =="
if bash -n "$ROOT/install.sh"; then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo "== 3. forged-receipt attack (T1 acceptance) =="
if $PY "$ROOT/qa/attacks/forged_receipt_poc.py"; then echo "  ok"; else echo "  FAIL (loophole present — this is T1)"; fail=1; fi

echo "== 4. CLI regression suite =="
# Run by module name from qa/ so it works on Python <3.12 (which can't take a file path).
if ( cd "$ROOT/qa" && $PY -m unittest test_regressions -v ); then echo "  ok"; else echo "  FAIL"; fail=1; fi

echo
if [ "$fail" = 0 ]; then echo "ALL GREEN"; else echo "SOME CHECKS FAILED (see above)"; fi
exit $fail
