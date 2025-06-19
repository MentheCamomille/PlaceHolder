#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TIOCSETD 0x5423

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /dev/pts/X\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    int ldisc = 30;  
    if (ioctl(fd, TIOCSETD, &ldisc) < 0) {
        perror("ioctl TIOCSETD");
        close(fd);
        return 1;
    }

    printf("Line discipline 1337 appliquée à %s\n", argv[1]);
    close(fd);
    return 0;
}
