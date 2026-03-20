#!/bin/bash

# Dieses Skript automatisiert den Bauprozess, um einen Multiboot-kompatiblen Kernel
# und eine bootfähige ISO-Datei mit GRUB zu erstellen.

# Überprüfen, ob die erforderlichen Tools installiert sind
if ! command -v nasm &> /dev/null
then
    echo "NASM (Netwide Assembler) wurde nicht gefunden. Bitte installiere es mit 'sudo apt install nasm'."
    exit 1
fi

if ! command -v g++ &> /dev/null
then
    echo "g++ (GCC C++ Compiler) wurde nicht gefunden. Bitte installiere es mit 'sudo apt install build-essential'."
    exit 1
fi

if ! command -v grub-mkrescue &> /dev/null
then
    echo "GRUB-Tools wurden nicht gefunden. Bitte installiere sie mit 'sudo apt install xorriso grub-pc-bin grub-efi-amd64-bin'."
    exit 1
fi

echo "--- Starte den Build-Prozess ---"

# 1. Kernel kompilieren
echo "1. Kompiliere den C++-Kernel (kernel.cpp)..."
nasm -f elf32 boot.s -o boot.o
g++ -m32 -ffreestanding -fno-pie -c kernel.cpp -o kernel.o
g++ -m32 -ffreestanding -fno-pie -c shell.cpp -o shell.o
g++ -m32 -ffreestanding -fno-pie -c mos-classic.cpp -o kernel-classic.o

# Wallpaper und Icons vorbereiten
echo "1b. Bereite Medien-Assets vor..."
convert fds.png -resize 800x600! -depth 8 rgba:fds.raw
objcopy -I binary -O elf32-i386 -B i386 fds.raw fds.o

# Icons
for icon in edit folder calc off files calcu; do
    convert ${icon}.png -depth 8 rgba:${icon}.raw
    objcopy -I binary -O elf32-i386 -B i386 ${icon}.raw ${icon}.o
done

# Logos
for logo in logo1 logo2; do
    convert ${logo}.png -depth 8 rgba:${logo}.raw
    objcopy -I binary -O elf32-i386 -B i386 ${logo}.raw ${logo}.o
done

if [ $? -ne 0 ]; then
    echo "Fehler beim Vorbereiten der Assets."
    exit 1
fi

# 2. Kernel verknüpfen
echo "2. Verknüpfe den Kernel mit linker.ld..."
ld -m elf_i386 -T linker.ld -o kernel.bin boot.o kernel.o shell.o fds.o edit.o folder.o calc.o off.o logo1.o logo2.o files.o calcu.o
if [ $? -ne 0 ]; then
    echo "Fehler beim Verknüpfen des Kernels."
    exit 1
fi

echo "2b. Verknüpfe den Classic-Kernel..."
ld -m elf_i386 -T linker.ld -o kernel-classic.bin boot.o kernel-classic.o
if [ $? -ne 0 ]; then
    echo "Fehler beim Verknüpfen des Classic-Kernels."
    exit 1
fi

# 3. Verzeichnisstruktur für das ISO-Image erstellen
echo "3. Erstelle die ISO-Verzeichnisstruktur..."
mkdir -p isodir/boot/grub

# 4. Kernel in das ISO-Verzeichnis kopieren
echo "4. Kopiere den Kernel in das ISO-Verzeichnis..."
cp kernel.bin isodir/boot/kernel.bin
cp kernel-classic.bin isodir/boot/kernel-classic.bin

# 5. GRUB-Konfigurationsdatei in das ISO-Verzeichnis kopieren
echo "5. Kopiere die GRUB-Konfigurationsdatei..."
cp grub.cfg isodir/boot/grub/grub.cfg

# 6. Bootfähiges ISO-Image erstellen
echo "6. Erstelle die bootfähige ISO-Datei mit grub-mkrescue..."
grub-mkrescue -o myos.iso isodir
if [ $? -ne 0 ]; then
    echo "Fehler beim Erstellen der ISO-Datei."
    exit 1
fi

# 7. Aufräumen der temporären Dateien
echo "7. Lösche temporäre Dateien..."
rm -r isodir kernel.o kernel.bin kernel-classic.o kernel-classic.bin

echo "--- Build-Prozess abgeschlossen! ---"
echo "Die bootfähige Datei 'myos.iso' wurde erfolgreich erstellt."
echo "Du kannst diese Datei nun als virtuelles optisches Laufwerk in VirtualBox verwenden."

./qemu.sh