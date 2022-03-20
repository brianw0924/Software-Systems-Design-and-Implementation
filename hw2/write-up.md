# Makefile
```bash
make KDIR=/PATH/TO/linux-5.4-source CROSS=aarch64-linux-gnu-
```

# Hide/Unhide
* Linux kernel modules are stored in doubly linked list.
* To hide the rootkit, I simply remove it from the doubly linked list by list_del(), and remember to store the pointer of the prev LKM.
* To unhide the rootkit, I use list_add() to adding it back to the doubly linked list.

# Masquerade Process Name
* The process name is stored in the comm[] in task_struct.
* To masquerade it, I use get_task_comm to get the comm[], and then directly strcpy the new name to comm[].

# Hook/Unhook System Call

# Test programs

For Hide/Unhide, simply run the test_hide program. If the rootkit is already hidden, the program will unhide it; If it's not hidden, the program will hide it.
```bash
./test_hide
```

For Masquerade, run the test_masq program with a positive integer argument, indicating the number of process name you want to masquerade. The user have to enter the orig_name and new_name in order.
```bash
./test_masq <NUM_MASQ>
```

For Hook/Unhook, simply run the test_hook program.
```bash
./test_hook
```

# References
* https://xcellerator.github.io/posts/linux_rootkits_01/
* https://xcellerator.github.io/posts/linux_rootkits_02/
* https://github.com/LTD-Beget/tcpsecrets/blob/master/tcpsecrets.c
