#include <linux/module.h>
#include <linux/kthread.h>

static struct task_struct *thread = NULL;

static int threaded_func(void *data)
{
    char *kdata = data;
    while (kthread_should_stop() == 0)
        pr_info("thread: %s: %s\n", thread->comm, kdata);

    return 0;
}

static __init int thread_init(void)
{
    thread = kthread_run(threaded_func, "data", "thread_%d", 42);

    pr_info("thread: insmoded\n");

    if (IS_ERR(thread))
    {
        pr_err("thread: faield to create a kthread\n");
        return PTR_ERR(thread);
    }

    pr_info("thread: kthread started\n");

    return 0;
}

static __exit void thread_exit(void)
{
    if (thread)
    {
        kthread_stop(thread);
        pr_info("thread: kthread stopped\n");
    }

    pr_info("thread: rmmoded\n");
}

module_init(thread_init);
module_exit(thread_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Threaded module");
MODULE_AUTHOR("Jules Aubert");
