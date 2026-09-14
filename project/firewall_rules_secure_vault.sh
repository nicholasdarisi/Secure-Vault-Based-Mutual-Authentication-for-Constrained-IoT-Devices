#!/usr/bin/env bash
set -euo pipefail

# Secure Vault prototype host-firewall policy.
# IoT Flask service: TCP port 5050.
# Run with root privileges on the Linux server host.

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

iptables -A INPUT -p tcp --dport 5050 \
  -m hashlimit \
  --hashlimit-name flask_iot_limit \
  --hashlimit-above 2/sec \
  --hashlimit-burst 10 \
  --hashlimit-mode srcip \
  -j DROP

iptables -A INPUT -p tcp --dport 5050 \
  -m connlimit \
  --connlimit-above 10 \
  --connlimit-mask 32 \
  -j DROP

iptables -A INPUT -p tcp --dport 5050 -j ACCEPT
