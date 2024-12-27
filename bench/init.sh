#!/usr/bin/env bash

# set -eu
set -x

# Setup wireguard
# DONT assume configs exist in: /config/wg_confs/wg0.conf

# Write the client configuration to the file
cat <<EOF > "wg0.conf"
[Interface]
PrivateKey = $PRIVATE_KEY
ListenPort = ${WG_PORT:-51820}

[Peer]
PublicKey = $PEER_PUBLIC_KEY
${ENDPOINT:+Endpoint = $ENDPOINT}
AllowedIPs = $ALLOWED_IPS
EOF

# Assume that the userspace implementation is called 'wireguard' and is placed in PATH
WG_SUDO=1 "${WIREGUARD_CMD:-wireguard}" wg0

ip a add dev wg0 $ADDRESS
ip l set dev wg0 up
# TODO: Make sure to only provide 1 ALLOWED_IPS
ip r add dev wg0 $ALLOWED_IPS
wg setconf wg0 wg0.conf

"$@"
