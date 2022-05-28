# 2022 Spring CSIE 5374 Assignment
## Assignment 1
In assignment 1, you are asked to write a simple shell. A shell itself is just a user program. Operating systems like Linux rely on shells to run programs. For instance, the bash shell is an executable called bash. When you log into a computer running Linux based systems, the shell's program, such as bash (located in /bin/bash) gets executed.

You should follow the requirements listed below to implement your shell. You are also asked to modify the Linux kernel to support a new system call. Your shell should run on top of the modified 

Linux kernel to invoke the new system call. You can follow the instructions below to set up the environment for testing your shell and the modified kernel. Specifically, you will first boot the modified Linux in an Armv8 virtual machine using QEMU, then run your shell program on the Linux.

This assignment is inspired and modified from Homework 1 in W4118 Operating Systems offered at Columbia
## Assignment 2
In assignment 2, you have to write a simple rootkit and provide the following functions: hide/unhide
module, masquerade process name, hook/unhook syscall. Rootkit as you might have heard before, is
essentially the malware that runs in the kernel space.

To achieve these functions, you must implement it as a loadable kernel module (LKM). LKM runs in kernel mode and allows access to all kernel internal structures/functions. It can be used to extend the functionality of the running kernel, and thus it is also often used to implement device drivers to support new hardware.
In this assignment, we provide an LKM template as a starting point for you. You should modify the module source to meet assignment requirements. You should also write a user space program to test the functionality of your rootkit module. Both the rookit and the test program must run on an AArch64 machine. We use QEMU to emulate this, as you did in assignment 1.
In this assignment, you are NOT allowed to modify the kernel source. Your rootkit should work as an
independent module on the mainline Linux v5.4.
## Assignment 3
The page table of a task maps virtual memory addresses to physical memory addresses. In normal cases, page tables are managed by the OS kernel such as Linux, and are inaccessible from userspace. 

Inspired by Dune, we want to allow userspace tasks to view their own and other userspace task's page tables. As mentioned in the Dune paper, this information has various benefits, such as improving garbage collection.

However, this also increases the kernel's attack surface, as one task can manipulate another's page table to carry attacks such as code injection. In assignment 3, we ask you to explore these fronts by making page tables accessible to userspace tasks.

First, you should add a new system call expose_pte to the Linux kernel v5.4. The system call exposes a given task's page tables to userspace. Next, you are asked to write userspace programs to test the capabilities of the system call. Your modified Linux kernel and the test program must run on the same AArch64 machine emulated by QEMU, as you did in the first two assignments.
## Assignment 4
Unlike regular filesystems in Linux (ex: ext4) a psuedo filesystem resides in memory entirely and consumes no storage space. It provides the filesystem hierarchy (e.g. folders and files) like normal filesystem, to store files and directory entries that expose kernel or other information or support system configuration.

The most well-known example of a pseudo file system is procfs (process file system), which is traditionally mounted at the path /proc.
Most of it is read-only, but some files allow kernel variables and behavior to be modified (more details).

In addition to procfs, Linux supports other pseudo file systems such as sysfs (mounted in /sys), ramfs, devpts, debugfs, tmpfs, etc.

For this assignment, you are to implement a pseudo file system called SeccompFS, which exposes seccomp system call trace of the currently running processes and allows users to install seccomp filter for a targeted process.

This assignment will demonstrate Linux's filesystems behavior and teach you how to construct a filesystem that can be mounted to anywere using the mount command.