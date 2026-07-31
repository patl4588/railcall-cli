#!/bin/bash
# One-time per clone: point git at the tracked .githooks/ dir so the
# pre-commit hook runs on every commit in this repo. Idempotent — safe
# to re-run.
#
# This is --local so it doesn't clobber your global hooks config in other
# repos. If you're a maintainer working across railcall-contrib +
# railcall-core + railcall-engine, run this in each.
#
# The hook itself enforces install.sh drift (see .githooks/pre-commit for
# rationale). CI also enforces the same check via qa/run.sh step 2b, so
# an unhooked clone still red's the PR — this just fails locally faster.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.."
git config --local core.hooksPath .githooks
echo "✓ git hooks now sourced from .githooks/"
echo "  installed: $(ls .githooks | tr '\n' ' ')"
