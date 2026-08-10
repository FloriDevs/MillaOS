#/bin/bash
echo "installing iso tools, grub and grub-efi using apt"
sudo apt install xorriso grub-pc-bin grub-efi-amd64-bin
echo "installing build-essential using apt"
sudo apt install build-essential
echo "installing nasm using apt"
sudo apt install nasm
echo "installing imagemagick using apt"
sudo apt install imagemagick
