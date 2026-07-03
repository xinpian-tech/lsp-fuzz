#!/usr/bin/env bash
# Self-test that build-zaozi-backdrop.sh's verify mode is genuinely FAIL-CLOSED: it must reject a
# backdrop whose SemanticDB output is missing, whose BSP config is absent, or whose content has
# drifted from the recorded snapshot hash. Operates on a throwaway copy of a real backdrop.
#
#   BACKDROP_OUT=<a-built-backdrop> ./check-backdrop-failclosed.sh
set -euo pipefail
cd "$(dirname "$0")"
SRC="${BACKDROP_OUT:?set BACKDROP_OUT to a backdrop built by build-zaozi-backdrop.sh}"
[ -f "$SRC/backdrop-metadata.json" ] || { echo "FAIL: $SRC is not a built backdrop"; exit 1; }

verify() { BACKDROP_OUT="$1" VERIFY_ONLY=1 ./build-zaozi-backdrop.sh >/dev/null 2>&1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
expect_reject() { # <label> <dir>
  if verify "$2"; then echo "FAIL: verify accepted a broken backdrop ($1)"; fail=1
  else echo "OK: verify rejected $1"; fi
}
expect_accept() { # <label> <dir>
  if verify "$2"; then echo "OK: verify accepted $1"
  else echo "FAIL: verify rejected a valid backdrop ($1)"; fail=1; fi
}

# Baseline: an untouched copy must be accepted.
cp -r "$SRC" "$tmp/valid"; expect_accept "an intact backdrop" "$tmp/valid"

# 1. Missing SemanticDB output.
cp -r "$SRC" "$tmp/no-sdb"; find "$tmp/no-sdb/semanticdb" -name '*.semanticdb' -delete
expect_reject "a backdrop with no SemanticDB output" "$tmp/no-sdb"

# 2. Absent BSP config.
cp -r "$SRC" "$tmp/no-bsp"; rm -f "$tmp/no-bsp/bsp/mill-bsp.json"
expect_reject "a backdrop with no BSP config" "$tmp/no-bsp"

# 3. Snapshot drift (content changed but metadata hash not).
cp -r "$SRC" "$tmp/drift"; f=$(find "$tmp/drift/semanticdb" -name '*.semanticdb' | head -1)
printf 'tampered' >> "$f"
expect_reject "a backdrop whose content drifted from the recorded hash" "$tmp/drift"

# 4. Tampered BSP config content (present, but no longer matches the recorded .bsp.sha256).
cp -r "$SRC" "$tmp/bsp-tamper"; printf '\n{"tampered":true}\n' >> "$tmp/bsp-tamper/bsp/mill-bsp.json"
expect_reject "a backdrop whose BSP config content drifted from the recorded hash" "$tmp/bsp-tamper"

[ "$fail" -eq 0 ] && echo "OK: build-zaozi-backdrop.sh verify mode is fail-closed" || echo "FAIL: fail-closed self-test had failures"
exit $fail
