#include <linux/module.h>

static char *ls_file = "/tmp";
module_param(ls_file, charp, 0644);
MODULE_PARM_DESC(ls_file, "File to list");

static int exec_ls(void)
{
    struct subprocess_info *sub_info = NULL;
    struct file *file = NULL;
    char *output_file = "/tmp/execls_output";
    char *cmd = NULL;
    char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int status = 0;
    char *buf = NULL;
    loff_t pos = 0;
    int len = 0;

    pr_info("execls: running ls on: %s\n", ls_file);
    cmd = kmalloc(4096, GFP_KERNEL);
    if (!cmd)
    {
        pr_err("execls: failed to allocate memory for cmd\n");
        return 1;
    }
    sprintf(cmd, "ls %s > %s", ls_file, output_file);
    char *argv[] = { "/bin/sh", "-c", cmd, NULL };


    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info == NULL)
    {
        pr_err("execls: failed to setup usermodehelper\n");
        kfree(cmd);
        return 1;
    }

    status = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    status = status >> 8;
    pr_info("execls: finished with exit status: %d\n", status);
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf)
    {
        pr_err("execls: failed to allocate memory for buffer\n");
        kfree(cmd);
        return 1;
    }

    file = filp_open(output_file, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("execls: failed to open file: %ld\n", PTR_ERR(file));
        kfree(buf);
        kfree(cmd);
        return 1;
    }

    len = kernel_read(file, buf, 4096, &pos);
    if (len < 0)
    {
        pr_err("execls: failed to read file\n");
        filp_close(file, NULL);
        kfree(buf);
        kfree(cmd);
        return 1;
    }
    else if (len == 4096)
    {
        pr_err("execls: buffer to read output file may be too short\n");
        filp_close(file, NULL);
        kfree(buf);
        kfree(cmd);
        return 1;
    }

    // TODO: Handle the read of a file until all the bytes have been read ;)
    // TODO: Handle stderr

    pr_info("execls: output:\n%s", buf);
    pr_info("\n");
    filp_close(file, NULL);
    kfree(buf);
    kfree(cmd);
    return 0;
}

static int __init execls_init(void)
{
    pr_info("execls: insmoded\n");
    return exec_ls();
}

static void __exit execls_exit(void)
{
    pr_info("execls: rmmoded\n");
}

module_init(execls_init);
module_exit(execls_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules Aubert");
MODULE_DESCRIPTION("Execute ls on a given directory");
