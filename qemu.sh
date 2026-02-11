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

QEMU_ARGS="-cdrom myos.iso -device rtl8139,netdev=n0 -netdev user,id=n0 -boot d -m 128"

# Check for HDD image
if [ -f "disk.img" ]; then
    echo "Hard Disk image found. Mounting as primary master (-hda)."
    QEMU_ARGS="$QEMU_ARGS -hda disk.img"
elif [ -f "usb.img" ]; then
    echo "USB image found. Mounting as primary master (-hda)."
    QEMU_ARGS="$QEMU_ARGS -hda usb.img"
fi

echo "Starting QEMU with RTL8139 Network Card..."
qemu-system-i386 $QEMU_ARGS
