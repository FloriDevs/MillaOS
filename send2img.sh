#!/bin/bash

# Überprüfen, ob beide Argumente übergeben wurden
if [ "$#" -ne 2 ]; then
    echo "Fehler: Falsche Anzahl an Argumenten."
    echo "Nutzung: $0 <datei_oder_ordner> <disk.img>"
    exit 1
fi

QUELLE="$1"
IMAGE="$2"

# Prüfen, ob die Quelldatei existiert
if [ ! -e "$QUELLE" ]; then
    echo "Fehler: Quelle '$QUELLE' existiert nicht."
    exit 1
fi

# Prüfen, ob das Ziel-Image existiert
if [ ! -f "$IMAGE" ]; then
    echo "Fehler: Image-Datei '$IMAGE' existiert nicht oder ist kein reguläres File."
    exit 1
fi

# Prüfen, ob mtools installiert ist
if ! command -v mcopy &> /dev/null; then
    echo "Fehler: 'mtools' ist nicht installiert."
    echo "Bitte installiere es (z.B. mit: sudo apt install mtools)"
    exit 1
fi

echo "Kopiere '$QUELLE' in das FAT-Image '$IMAGE'..."

# mcopy ausführen (-i gibt das Image an, -s kopiert rekursiv falls es ein Ordner ist)
# Das '::' signalisiert mtools das Hauptverzeichnis (Root) des FAT-Dateisystems
mcopy -i "$IMAGE" -s "$QUELLE" ::

if [ $? -eq 0 ]; then
    echo "Erfolgreich kopiert!"
else
    echo "Fehler beim Kopieren der Datei in das Image."
    exit 1
fi
