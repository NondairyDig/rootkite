#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define CDEV_DEVICE "controller"
static char buf[512+1];

int main(int argc, char *argv[])
{
    int fd, len;

    if (argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        exit(0);
    }

    if ((len = strlen(argv[1]) + 1) > 512) {
        printf("ERROR: String too long\n");
        exit(0);
    }

    if ((fd = open("/dev/" CDEV_DEVICE, O_RDWR)) == -1) {
        perror("/dev/" CDEV_DEVICE);
        exit(1);
    }

    printf("fd :%d\n",fd);

    if (read(fd, buf, len) == -1)
        perror("read()");
    else
        printf("Before: \"%s\".\n", buf);

    if (write(fd, argv[1], len) == -1)
        perror("write()");
    else
        printf("Wrote: \"%s\".\n", argv[1]);

    if (read(fd, buf, len) == -1)
        perror("read()"); 
    else    
        printf("After: \"%s\".\n", buf);

    if ((close(fd)) == -1) {
        perror("close()");
        exit(1);
    }

    exit(0);
}
