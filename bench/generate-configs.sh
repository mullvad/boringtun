#!/usr/bin/env bash
set -eu

# network: 10.13.13.1/24

# Stop all running containers and clean up podman networks
echo "Stopping containers and cleaning up networks..."
podman-compose down
podman network prune -f

# Define the base directory where WireGuard configurations will be stored
BASE_DIR="./data"

# Remove any old config files
rm -f "$BASE_DIR/wireguard-server/config/wg_confs/server.conf"
rm -f "$BASE_DIR/wireguard-client/config/wg_confs/client.conf"

# Create the necessary directories for the server and client configurations
mkdir -p "$BASE_DIR/wireguard-server/config/wg_confs"
mkdir -p "$BASE_DIR/wireguard-client/config/wg_confs"

# Generate WireGuard private and public keys (for both server and client)
# You can change these names if you want to use custom names
SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Write the server configuration to the file
cat <<EOF > "$BASE_DIR/wireguard-server/config/wg_confs/server.conf"
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.13.13.1/32
ListenPort = 51820
SaveConfig = true

# Example peer configuration (client)
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.13.13.2/32
EOF

chmod 600 "$BASE_DIR/wireguard-server/config/wg_confs/server.conf"

# Write the client configuration to the file
cat <<EOF > "$BASE_DIR/wireguard-client/config/wg_confs/client.conf"
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.13.13.2/32

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = wireguard-server:51820  # Use container name as the DNS name in Docker
AllowedIPs = 10.13.13.1/32
PersistentKeepalive = 25
EOF


chmod 600 "$BASE_DIR/wireguard-client/config/wg_confs/client.conf"

# Display the generated keys and configuration details
echo "WireGuard server and client configurations have been generated."
echo "Server private key: $SERVER_PRIVATE_KEY"
echo "Server public key: $SERVER_PUBLIC_KEY"
echo "Client private key: $CLIENT_PRIVATE_KEY"
echo "Client public key: $CLIENT_PUBLIC_KEY"

echo "Configuration files have been saved in the following locations:"
echo "Server config: $BASE_DIR/wireguard-server/config/wg_confs/server.conf"
echo "Client config: $BASE_DIR/wireguard-client/config/wg_confs/client.conf"

# Inform the user how to proceed
echo "You can now use 'docker-compose up -d' to bring up the WireGuard containers."
