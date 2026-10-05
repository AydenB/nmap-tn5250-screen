#!/usr/bin/env bash
# Offline test for tn5250-screen.nse.
#
# Starts the fake TN5250 server (replaying a captured IBM i sign-on screen),
# runs the NSE script against it on localhost, and checks that the rendered
# screen and the hidden password field come back as expected.
#
# Requires: nmap, python3. No network access needed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PORT="${PORT:-2323}"

pass=0
fail=0
check() { # check <description> <pattern> <output-file>
  if grep -qF "$2" "$3"; then
    echo "  ok   - $1"
    pass=$((pass + 1))
  else
    echo "  FAIL - $1 (expected to find: $2)"
    fail=$((fail + 1))
  fi
}

echo "Starting fake tn5250 server on port $PORT ..."
python3 "$HERE/fake_tn5250_server.py" --port "$PORT" >/tmp/tn5250_fake.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null' EXIT
sleep 1

OUT="$(mktemp)"
echo "Running nmap tn5250-screen against 127.0.0.1:$PORT ..."
# The leading '+' forces the script to run regardless of its portrule, so we
# can test on a non-standard high port without root.
nmap --datadir "$ROOT" \
     --script "+$ROOT/scripts/tn5250-screen.nse" \
     --script-args "tn5250-screen.nossl=1,tn5250-screen.timeout=4000" \
     -p "$PORT" 127.0.0.1 -oN "$OUT" >/dev/null 2>&1

echo
echo "----- script output -----"
sed -n '/tn5250-screen/,/^$/p' "$OUT"
echo "--------------------------"
echo

check "sign-on banner rendered"      "your public IBM i server"       "$OUT"
check "server name label present"    "Server name"                    "$OUT"
check "user name prompt present"     "Your user name"                 "$OUT"
check "password prompt present"      "Password (max. 128)"            "$OUT"
check "visible user field at r5c25"  "(5, 25): visible input field"   "$OUT"
check "hidden password field r6c25"  "(6, 25): non-display input field, length 128" "$OUT"
check "copyright line rendered"      "COPYRIGHT IBM CORP"             "$OUT"

echo
echo "Passed: $pass  Failed: $fail"
rm -f "$OUT"
[ "$fail" -eq 0 ]
