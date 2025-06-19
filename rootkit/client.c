#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 4444 

enum {
    CMD_EXEC,
    CMD_GET,
    CMD_PUT,
    CMD_EXIT
};

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <IP> <filename>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;          // adresses IPv4
    server.sin_port = htons(PORT);        // port converti en format réseau
    inet_pton(AF_INET, argv[1], &server.sin_addr); // conversion ip en binaire

    // essayer de se connecter au serveur 
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Connection failed"); 
        return 1;
    }


    // // ouvre le fichier en mode binaire 
    // FILE *f = fopen(argv[2], "rb");

    // char buffer[1024];
    // int n;

    // // lecture du fichier par blocs de 1024 octets et envoi au serveur
    // while ((n = fread(buffer, 1, 1024, f)) > 0) {
    //     send(sock, buffer, n, 0);  // envoyer les données lues
    // }
    char *inforecv = malloc(6);
    recv(sock, inforecv, 6,0);
    printf("rcv %s\n",inforecv);
    int key = atoi(inforecv);
    key -= 1;
    key /= 100;
    char parsed[4];
    char pass[34] = "base_pass";
    my_itoa(key, parsed);
    strcat(pass,parsed);
    send(sock, pass, strlen(pass),0);
    //fclose(f);
    char receive[101];
    int len = recv(sock, receive, 100,0);
    receive[len] = '\0'; 
    printf("response %s\n",receive);
    send(sock,CMD_EXIT, sizeof(int), 0);
    close(sock);
    char receive2[101];
    int len2 = recv(sock, receive2, 100,0);
    printf("response %s\n",receive2);

    return 0;
}
