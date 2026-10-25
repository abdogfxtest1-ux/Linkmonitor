#!/usr/bin/env bash
# بينزّل Tor (مع الـ bridges) و wireproxy لـ Windows جوه vendor/
set -euo pipefail
TOR=15.0.26
WP=v1.1.3
cd "$(dirname "$0")"
rm -rf vendor && mkdir -p vendor/tor
curl -fsSL -o tor.tgz "https://dist.torproject.org/torbrowser/$TOR/tor-expert-bundle-windows-x86_64-$TOR.tar.gz"
tar -xzf tor.tgz -C vendor/tor && rm tor.tgz
curl -fsSL -o wp.tgz "https://github.com/windtf/wireproxy/releases/download/$WP/wireproxy_windows_amd64.tar.gz"
tar -xzf wp.tgz -C vendor wireproxy.exe && rm wp.tgz
ls vendor vendor/tor
