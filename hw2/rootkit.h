#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#define MASQ_LEN	16
#define IOCTL_MOD_HOOK 9
#define IOCTL_MOD_HIDE 99
#define IOCTL_MOD_MASQ 999

struct masq_proc {
	char new_name[MASQ_LEN];
	char orig_name[MASQ_LEN];
};

struct masq_proc_req {
	size_t len;
	struct masq_proc *list;
};

#endif /* __ROOTKIT_HW2_H */
