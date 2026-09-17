#!/bin/bash

# Ins Verzeichnis des Skripts wechseln
cd "$(dirname "$0")"

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

if ! command -v mformat &> /dev/null
then
    echo "mformat wurde nicht gefunden. Bitte installiere 'mtools' mit 'sudo apt install mtools'."
    exit 1
fi

echo "--- Starte den Build-Prozess ---"

# 1. Kernel kompilieren
echo "1. Kompiliere den C++-Kernel (kernel.cpp)..."
nasm -f elf32 boot.s -o boot.o
g++ -m32 -ffreestanding -fno-pie -c kernel.cpp -o kernel.o
g++ -m32 -ffreestanding -fno-pie -c shell.cpp -o shell.o
g++ -m32 -ffreestanding -fno-pie -c mpra.cpp -o mpra.o
g++ -m32 -ffreestanding -fno-pie -c cli.cpp -o cli.o

# Wallpaper und Logos vorbereiten
echo "1b. Bereite Medien-Assets vor..."
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

if [ $? -ne 0 ]; then
    echo "Fehler beim Vorbereiten der Assets."
    exit 1
fi

# Wallpapers auf das Festplatten- und USB-Image kopieren
if [ -f "disk.img" ]; then
    echo "Kopiere Wallpapers auf die HDD (disk.img)..."
    for i in {1..9}; do
        mcopy -o -i disk.img wp${i}.raw ::WP${i}.RAW
    done
fi

if [ -f "usb.img" ]; then
    echo "Kopiere Wallpapers auf das USB-Image (usb.img)..."
    for i in {1..9}; do
        mcopy -o -i usb.img wp${i}.raw ::WP${i}.RAW
    done
fi

# 2. Kernel verknüpfen (nur wp1 und resized logos werden statisch gelinkt)
echo "2. Verknüpfe den Kernel mit linker.ld..."
ld -m elf_i386 -T linker.ld -o kernel.bin boot.o kernel.o shell.o mpra.o cli.o wp1.o logo1.o logo2.o
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
rm -rf isodir kernel.o shell.o mpra.o cli.o kernel.bin *.raw *.o

echo "--- Build-Prozess abgeschlossen! ---"
echo "Die bootfähige Datei 'myos.iso' wurde erfolgreich erstellt."
