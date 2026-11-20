#!/bin/sh
# Blocks all UDP except DNS on this Linux machine, IPv4 and IPv6, loopback included, as on a company
# or hotel network: Tailcat then reaches the other side over its DERP relays only. Needs root (sudo).
#   scripts/e2e-udp-block.sh on && TAILPOCKET_LIVE=1 go test -run TestLiveRelayOnly ./e2e; scripts/e2e-udp-block.sh off
# Check it holds: a STUN query (stun.l.google.com:19302) times out while HTTPS still works. Same-Wi-Fi
# pairing needs mDNS, which is UDP: skip TestLiveSameWiFiPairing while the block is on.
set -eu
for ipt in iptables ip6tables; do
  case "${1:?usage: e2e-udp-block.sh on | off}" in
    on)
      # Silent drop of what arrives (like an upstream firewall): sends succeed, nothing comes back.
      # UDP_BLOCK_CHAINS="OUTPUT INPUT" also refuses sends (EPERM).
      for ch in ${UDP_BLOCK_CHAINS:-INPUT}; do
        sudo $ipt -C $ch -p udp --dport 53 -j ACCEPT 2>/dev/null || sudo $ipt -I $ch 1 -p udp --dport 53 -j ACCEPT
        sudo $ipt -C $ch -p udp --sport 53 -j ACCEPT 2>/dev/null || sudo $ipt -I $ch 2 -p udp --sport 53 -j ACCEPT
        sudo $ipt -C $ch -p udp -j DROP 2>/dev/null || sudo $ipt -A $ch -p udp -j DROP
      done ;;
    off)
      for ch in OUTPUT INPUT; do
        while sudo $ipt -D $ch -p udp -j DROP 2>/dev/null; do :; done
        while sudo $ipt -D $ch -p udp --dport 53 -j ACCEPT 2>/dev/null; do :; done
        while sudo $ipt -D $ch -p udp --sport 53 -j ACCEPT 2>/dev/null; do :; done
      done ;;
  esac
done
sudo iptables -S | grep -i udp || true
