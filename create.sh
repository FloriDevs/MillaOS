#!/bin/bash

# Function to create a disk image
create_image() {
    local filename=$1
    local size_mb=$2
    local label=$3
    
    echo "Creating $filename ($size_mb MB)..."
    
    # Create empty file
    dd if=/dev/zero of=$filename bs=1M count=$size_mb
    
    # Format as FAT16 (requires dosfstools)
    if command -v mkfs.fat &> /dev/null; then
        mkfs.fat -F 16 -n "$label" $filename
        echo "Formatted as FAT16."
    elif command -v mkfs.vfat &> /dev/null; then
        mkfs.vfat -F 16 -n "$label" $filename
        echo "Formatted as FAT16."
    else
        echo "Warning: mkfs.fat not found. The disk will be unformatted."
    fi
}

if [ "$1" == "--qemu" ]; then
    create_image "disk.img" 64 "MILLA_HDD"
    echo "Created disk.img for QEMU."
    echo "Run './qemu.sh' to use it."
elif [ "$1" == "--usb" ]; then
    create_image "usb.img" 128 "MILLA_USB"
    echo "Created usb.img."
    echo "You can write this to a USB stick with: sudo dd if=usb.img of=/dev/sdX bs=4M"
    echo "WARNING: Be careful with dd!"
else
    echo "Usage: ./create.sh [--qemu | --usb]"
    echo "  --qemu : Create a 64MB hard disk image (disk.img)"
    echo "  --usb  : Create a 128MB USB disk image (usb.img)"
fi
