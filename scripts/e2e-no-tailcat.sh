#!/bin/sh
# Proves from outside the process that a host and phone without Tailcat send nothing off the machine:
# runs the e2e no-Tailcat tests as a throwaway user and counts, with iptables, every IPv4 and IPv6
# packet that user sends anywhere but loopback (DNS included). The count must be 0. As a control, the
# same count is taken for a run with Tailcat (TestLiveQRPairConnectRestartRevoke, needs internet),
# which must be above 0. Linux, root (sudo), Go on PATH.
#   scripts/e2e-no-tailcat.sh
set -eu
user=tpnotc
bin=$(mktemp -d)/e2e.test
go test -c -o "$bin" ./e2e
chmod 755 "$(dirname "$bin")" "$bin"
id -u $user >/dev/null 2>&1 || sudo useradd -M -s /usr/sbin/nologin $user
uid=$(id -u $user)
count() { # packets $user sent off loopback since the chain was made
  for ipt in iptables ip6tables; do sudo $ipt -L TPNOTC -v -n -x | awk 'NR>2{s+=$1} END{print s+0}'; done | awk '{s+=$1} END{print s}'
}
reset() {
  for ipt in iptables ip6tables; do
    sudo $ipt -D OUTPUT ! -o lo -m owner --uid-owner $uid -j TPNOTC 2>/dev/null || true
    sudo $ipt -F TPNOTC 2>/dev/null || true
    sudo $ipt -X TPNOTC 2>/dev/null || true
    [ "${1:-}" = off ] && continue
    sudo $ipt -N TPNOTC
    sudo $ipt -A TPNOTC -j RETURN
    sudo $ipt -I OUTPUT 1 ! -o lo -m owner --uid-owner $uid -j TPNOTC
  done
}
trap 'reset off' EXIT
reset
# The tests must pass too: a failing run that sends nothing proves nothing.
log=$(dirname "$bin")/run.log
(cd /tmp && sudo -u $user env HOME=/tmp "$bin" -test.count=1 -test.v -test.run 'TestNoTailcat') > "$log" 2>&1 || {
  cat "$log"; echo "FAIL: the no-Tailcat tests failed"; exit 1; }
grep -E '^(---|ok|FAIL|PASS)|_test.go' "$log"
n=$(count); echo "no-Tailcat run: $n packets off loopback"
[ "$n" -eq 0 ] || { echo "FAIL: the no-Tailcat run sent packets off the machine"; exit 1; }
reset
(cd /tmp && sudo -u $user env HOME=/tmp TAILPOCKET_LIVE=1 "$bin" -test.count=1 -test.run 'TestLiveQRPairConnectRestartRevoke' -test.timeout 5m) > "$log" 2>&1 || {
  cat "$log"; echo "FAIL: the Tailcat control run failed"; exit 1; }
tail -1 "$log"
c=$(count); echo "control run with Tailcat: $c packets off loopback"
[ "$c" -gt 0 ] || { echo "FAIL: the control sent nothing, so the count proves nothing"; exit 1; }
echo PASS
