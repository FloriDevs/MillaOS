#!/bin/bash

# Ins Verzeichnis des Skripts wechseln
cd "$(dirname "$0")"

# Dieses Skript automatisiert den Bauprozess, um einen Multiboot-kompatiblen Kernel
# und eine bootfähige ISO-Datei mit GRUB zu erstellen.

# Überprüfen, ob die erforderlichen Tools installiert sind
if ! command -v nasm &> /dev/null
then
    echo "NASM (Netwide Assembler) isn't installed please install it with 'sudo apt install nasm'."
    exit 1
fi

if ! command -v g++ &> /dev/null
then
    echo "g++ (GCC C++ Compiler) isn't installed please install it with 'sudo apt install build-essential'."
    exit 1
fi

if ! command -v grub-mkrescue &> /dev/null
then
    echo "GRUB-Tools isn't installed please install it with 'sudo apt install xorriso grub-pc-bin grub-efi-amd64-bin'."
    exit 1
fi

if ! command -v mformat &> /dev/null
then
    echo "mformat isn't installed please install it with  mit 'sudo apt install mtools'."
    exit 1
fi

echo "--- Start process ---"

# 1. Kernel kompilieren
echo "1. Compiling the Kernel and co (kernel.cpp, shell.cpp, mpra.cpp, cli.cpp)..."
nasm -f elf32 boot.s -o boot.o
g++ -m32 -ffreestanding -fno-pie -c kernel.cpp -o kernel.o
g++ -m32 -ffreestanding -fno-pie -c shell.cpp -o shell.o
g++ -m32 -ffreestanding -fno-pie -c mpra.cpp -o mpra.o
g++ -m32 -ffreestanding -fno-pie -c cli.cpp -o cli.o

# Wallpaper und Logos vorbereiten
echo "1b. Getting images ready..."
convert "wallpapers/MillaOS-simple.png" -resize 800x600! -depth 8 rgba:wp1.raw
objcopy -I binary -O elf32-i386 -B i386 wp1.raw wp1.o
convert "wallpapers/MillaOS-field.png" -resize 800x600! -depth 8 rgba:wp2.raw
convert "wallpapers/FloriDevs.png" -resize 800x600! -depth 8 rgba:wp3.raw
convert "wallpapers/Way.jpg" -resize 800x600! -depth 8 rgba:wp4.raw
convert "wallpapers/Wonne.jpg" -resize 800x600! -depth 8 rgba:wp5.raw
convert "wallpapers/forest.jpg" -resize 800x600! -depth 8 rgba:wp6.raw
convert "wallpapers/frozen sea 2.jpg" -resize 800x600! -depth 8 rgba:wp7.raw
convert "wallpapers/frozen sea.jpg" -resize 800x600! -depth 8 rgba:wp8.raw
convert "wallpapers/sunset.jpg" -resize 800x600! -depth 8 rgba:wp9.raw

# Logos (resized to actual drawn dimensions: logo1: 100x100, logo2: 80x80)
convert logo1.png -resize 100x100! -depth 8 rgba:logo1.raw
objcopy -I binary -O elf32-i386 -B i386 logo1.raw logo1.o
convert logo2.png -resize 80x80! -depth 8 rgba:logo2.raw
objcopy -I binary -O elf32-i386 -B i386 logo2.raw logo2.o

# Sample BMP images for image viewer
convert logo1.png -resize 100x100! -depth 8 bmp3:logo1.bmp
convert logo2.png -resize 80x80! -depth 8 bmp3:logo2.bmp
convert "wallpapers/FloriDevs.png" -resize 320x240! -depth 8 bmp3:flori.bmp

if [ $? -ne 0 ]; then
    echo "Error: can't prepare the Assets."
    exit 1
fi

# 2. Kernel verknüpfen (nur wp1 und resized logos werden statisch gelinkt)
echo "2.Linking using the linker.ld..."
ld -m elf_i386 -T linker.ld -o kernel.bin boot.o kernel.o shell.o mpra.o cli.o wp1.o logo1.o logo2.o
if [ $? -ne 0 ]; then
    echo "Error linking the kernel."
    exit 1
fi



# 3. Verzeichnisstruktur für das ISO-Image erstellen
echo "3. create iso..."
mkdir -p isodir/boot/grub

cp kernel.bin isodir/boot/kernel.bin
cp grub.cfg isodir/boot/grub/grub.cfg


grub-mkrescue -o MillaOS-x86.iso isodir
if [ $? -ne 0 ]; then
    echo "Error creating the iso"
    exit 1
fi

# 7. Aufräumen der temporären Dateien
echo "7. deleting temp. files..."
rm -rf isodir kernel.o shell.o mpra.o cli.o kernel.bin *.raw *.o *.bmp

echo "--- Build-Prozess finished! ---"
echo "'MillaOS-x86.iso' created successfully."
