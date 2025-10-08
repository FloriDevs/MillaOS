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
g++ -m32 -ffreestanding -fno-pie -c kernel.cpp -o kernel.o
if [ $? -ne 0 ]; then
    echo "Fehler beim Kompilieren des Kernels."
    exit 1
fi

# 2. Kernel verknüpfen
echo "2. Verknüpfe den Kernel mit linker.ld..."
ld -m elf_i386 -T linker.ld -o kernel.bin kernel.o
if [ $? -ne 0 ]; then
    echo "Fehler beim Verknüpfen des Kernels."
    exit 1
fi

# 3. Verzeichnisstruktur für das ISO-Image erstellen
echo "3. Erstelle die ISO-Verzeichnisstruktur..."
mkdir -p isodir/boot/grub

# 4. Kernel in das ISO-Verzeichnis kopieren
echo "4. Kopiere den Kernel in das ISO-Verzeichnis..."
cp kernel.bin isodir/boot/kernel.bin

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
rm -r isodir kernel.o kernel.bin

echo "--- Build-Prozess abgeschlossen! ---"
echo "Die bootfähige Datei 'myos.iso' wurde erfolgreich erstellt."
echo "Du kannst diese Datei nun als virtuelles optisches Laufwerk in VirtualBox verwenden."

