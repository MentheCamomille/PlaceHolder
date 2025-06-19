#include <linux/module.h>
#include <linux/cdev.h>

dev_t dev = 0;
static struct class *dev_class = NULL;
static struct cdev *cdev_struct = NULL;

static char *alphabet = NULL;
static size_t alphabet_len = 0;

module_param(alphabet, charp, 0);
MODULE_PARM_DESC(alphabet, "Alphabet to use for random bytes");


static ssize_t epirandom_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    unsigned char random_byte = 0;
    size_t i = 0;
    ssize_t n = 0;
    char *kbuf = kmalloc(len, GFP_KERNEL);

    if (kbuf == NULL)
        return -1;

    if (len < 1)
        return 0;

    for (i = 0; i != len; ++i)
    {
        get_random_bytes(&random_byte, 1);
        if (alphabet != NULL)
            kbuf[i] = alphabet[random_byte % alphabet_len];
        else
            kbuf[i] = random_byte;
    }

        n = copy_to_user(buf, kbuf, len);
        kfree(kbuf);
        if (n != 0)
        {
            pr_err("epirandom: Cannot copy %zu bytes to userspace\n", n);
            return -1;
        }

    return len;
}

static struct file_operations file_ops = {
    .owner = THIS_MODULE,
    .read = epirandom_read,
};


static char *set_devnode(const struct device *dev, umode_t *mode)
{
    if (mode != NULL)
        *mode = 0666;
    return NULL;
}

static int setup_device(void)
{

    if ((alloc_chrdev_region(&dev, 0, 1, "epirandom")) < 0)
    {
        pr_err("epirandom: Cannot allocate major number for device\n");
        return -1;
    }
    pr_info("Major = %d Minor = %d \n", MAJOR(dev), MINOR(dev));


    dev_class = class_create("epirandom");
    if (IS_ERR(dev_class))
    {
        pr_err("epirandom: Error creating class\n");
        unregister_chrdev_region(dev, 1);
        return -1;
    }
    dev_class->devnode = set_devnode;

    if (IS_ERR(device_create(dev_class, NULL, dev, NULL, "epirandom")))
    {
        pr_err("epirandom: Error creating device\n");
        class_destroy(dev_class);
        unregister_chrdev_region(dev, 1);
        return -1;
    }

    if (alphabet != NULL)
        alphabet_len = strlen(alphabet);

    pr_info("epirandom: Device class created\n");
    return 0;
}

static int setup_cdev(void)
{
    cdev_struct = cdev_alloc();
    cdev_struct->ops = &file_ops;
    cdev_struct->owner = THIS_MODULE;

    cdev_add(cdev_struct, dev, 1);
    return 0;
}

static int __init epirandom_init(void)
{
    if (setup_device() < 0)
        return -1;

    if (setup_cdev() < 0)
        return -1;

    pr_info("epirandom: Hello world!\n");
    pr_info("epirandom: alphabet = '%s'\n", alphabet);
    return 0;
}


static void __exit epirandom_exit(void)
{
    cdev_del(cdev_struct);
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    unregister_chrdev_region(dev, 1);
    pr_info("epirandom: Bye!\n");
}

module_init(epirandom_init);
module_exit(epirandom_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules Aubert");
MODULE_DESCRIPTION("Epirandom");
MODULE_VERSION("0.42");
