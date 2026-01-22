#!/bin/bash

# Define the port
PORT=8000

# Check if the HTTP server is running
if fuser -n tcp $PORT > /dev/null 2>&1; then
    echo "HTTP server is already running on port $PORT."
else
    echo "Starting HTTP server on port $PORT..."
    # Start Python HTTP server in the background
    python3 -m http.server $PORT --directory . &
    SERVER_PID=$!
    echo "HTTP server started causing PID $SERVER_PID"
    
    # Ensure server stops when script exits (optional, comment out if you want it to persist)
    # trap "kill $SERVER_PID" EXIT
fi

echo "Starting QEMU with RTL8139 Network Card..."
# -device rtl8139: Adds the specific network card MillaOS supports
# -netdev user,id=n0: Creates a user-mode network backend (Host=10.0.2.2)
qemu-system-i386 -cdrom myos.iso -device rtl8139,netdev=n0 -netdev user,id=n0 -boot d -m 128
