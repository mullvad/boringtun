#!/usr/bin/env bash

set -eu

# Create the wireguard configs
./setup.sh

# Inform the user how to proceed
echo "Starting WireGuard containers using podman Compose..."

# Start the containers using podman-compose
podman-compose up -d

# Wait for a moment to ensure the containers are up
sleep 5

# Verify if containers are running
podman-compose ps

# Inform the user that the setup is complete
echo "WireGuard containers have been started. You can check the logs with 'podman-compose logs'."
