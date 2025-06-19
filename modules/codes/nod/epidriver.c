#include <linux/module.h>

#define DEVICE_NAME "epidriver"

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static int major_num = 0;
static int device_open_count = 0;
static char *message = "Hello, APPING!\n";
static size_t message_len = 15;

static struct file_operations file_ops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

static ssize_t device_read(struct file *flip, char __user *buffer, size_t len, loff_t *offset)
{
    int bytes_read = 0;

    size_t i = 0;
    while (len != 0)
    {
        // i = [0 ... 14] = 15 values
        i = i % message_len;
        // put_user only send one byte to userland
        // hopefully we see a better way to send a buffer into userland in
        // Epirandom :)
        put_user(message[i], buffer);
        --len;
        ++i;
        ++buffer;
        ++bytes_read;
    }
    return bytes_read;
}

static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
    pr_alert("epidriver: Writing inside me is forbidden (even root cannot, cheh).");
    return -EINVAL;
}

static int device_open(struct inode *inode, struct file *file)
{
    if (device_open_count)
        return -EBUSY;

    device_open_count++;
    try_module_get(THIS_MODULE);
    return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}

static int __init epidriver_init(void)
{
    major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
    if (major_num < 0)
    {
        pr_alert("epidriver: Could not register device: %d\n", major_num);
        return major_num;
    }
    else
    {
        pr_info("epidriver: module loaded with device major number %d\n", major_num);
        return 0;
    }
}

static void __exit epidriver_exit(void)
{
    unregister_chrdev(major_num, DEVICE_NAME);
    pr_info("epidriver: Goodbye, APPING!\n");
}

module_init(epidriver_init);
module_exit(epidriver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules Aubert");
MODULE_DESCRIPTION("EpiDriver");
MODULE_VERSION("0.42");
