# Makefile
```bash
make KDIR=/PATH/TO/linux-5.4-source CROSS=aarch64-linux-gnu-
```

# Hide/Unhide
* Linux kernel modules are stored in doubly linked list.
* To hide the rootkit, I simply remove it from the doubly linked list by `list_del()`, and remember to store the pointer of the prev LKM.
* To unhide the rootkit, I use `list_add()` to adding it back to the doubly linked list.

# Masquerade Process Name
* The process name is stored in the `comm[]` in `task_struct`.
* To masquerade it, I use `get_task_comm` to get the `comm[]`, and then directly strcpy the new name to `comm[]`.

# Hook/Unhook System Call
* Use `lookup_symbols()` to find system call table, and then store the original system calls.
* Use `update_mapping_prot()` to change the memory area propities of system call table into writable.
* Write my own funtions for custom system calls, and then save them into system call table:
    * `asmlinkage long execve_hook (const struct pt_regs *regs)`
    I get the pathname from `regs->regs[0]`.
    * `asmlinkage long reboot_hook (const struct pt_regs *regs)`
    Simply return 0 to prevent kernel from shutting down.
* To unhook system calls, I restore original system calls back to the system call table.

# Test programs

For Hide/Unhide, simply run the test_hide program. If the rootkit is already hidden, the program will unhide it; If it's not hidden, the program will hide it.
```bash
./test_hide
```

For Masquerade, run the test_masq program with a positive integer argument, indicating the number of process name you want to masquerade. The user have to enter the orig_name and new_name in order.
```bash
./test_masq <NUM_MASQ>
```

For hook system call, simply run the test_hook program. The rootkit will automatically unhook after the LKM be removed.
```bash
./test_hook
```
# Contributions
* 王韋翰: Hide, Maspuerade system call
* 黃珮欣: Hook system call

# References
* https://xcellerator.github.io/posts/linux_rootkits_01/
* https://xcellerator.github.io/posts/linux_rootkits_02/
* https://github.com/LTD-Beget/tcpsecrets/blob/master/tcpsecrets.c
* https://javamana.com/2021/07/20210731105038539g.html