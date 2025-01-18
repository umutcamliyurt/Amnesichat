#!/bin/bash

# Define the directory for the torrc file (current directory)
TORRC_FILE="./torrc"

# Define the HTTP tunnel port (e.g., 8118)
HTTP_TUNNEL_PORT="8118"
SOCKS_PORT="9050"

# Backup existing torrc (if any) in the current directory
if [ -f "$TORRC_FILE" ]; then
    echo "Backing up existing torrc file to torrc.backup"
    cp "$TORRC_FILE" "$TORRC_FILE.backup"
fi

# Create a new torrc file with secure defaults and HTTPTunnelPort enabled
echo "Creating a new torrc configuration with secure defaults..."

cat > "$TORRC_FILE" <<EOL
# Tor configuration file
SocksPort $SOCKS_PORT
HTTPTunnelPort 127.0.0.1:$HTTP_TUNNEL_PORT
ExitPolicy accept *:*
DNSPort 0
ClientOnly 1
StrictNodes 1
DisableNetwork 0
EOL

# Set correct permissions for the torrc file (ensure only the user can read/write it)
echo "Setting correct permissions for torrc file..."
chmod 600 "$TORRC_FILE"

# Start Tor with the newly created torrc configuration (local torrc)
echo "Starting Tor with the new configuration (local torrc)..."

# Assuming Tor is already installed globally and can be run using 'tor' command
tor -f "$TORRC_FILE" &

# Wait for Tor to start and check if it is running
sleep 5

# Verify if Tor is running (check if tor process is active)
if pgrep -x "tor" > /dev/null; then
    echo "Tor has been successfully started with HTTPTunnelPort enabled."
else
    echo "Failed to start Tor. Please check the logs for errors."
fi
