#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/rbtree.h>
#include <linux/list.h>

#define ROOT_INO		UINT_MAX
#define BEGIN_INO		(UINT_MAX - 1)
#define CONFIG_INO		(UINT_MAX - 2)
#define PID_INO(pid)	(pid << 1)
#define LOG_INO(pid)	(1 + PID_INO(pid))

#define PIDINO_TO_LOGINO(ino)	(1 + ino)
#define INO_TO_PID(ino)			(ino >> 1)

unsigned pidstr_to_int(const struct qstr *qstr)
{
	const char *name = qstr->name;
	int len = qstr->len;
	unsigned n = 0;

	if (len > 1 && *name == '0')
		goto out;
	do {
		unsigned c = *name++ - '0';
		if (c > 9)
			goto out;
		if (n >= (~0U-9)/10)
			goto out;
		n *= 10;
		n += c;
	} while (--len > 0);
	return n;
out:
	return ~0U;
}


enum seccompfs_inode_type {
	ROOT,
	PID,
	BEGIN,
	CONFIG,
	LOG,
};


struct seccompfs_filter_entry {
	struct list_head entry_node;
	unsigned pid;
	unsigned len;
	unsigned short syscall_no[0];
};

struct seccompfs_inode {
	union {
		struct {
			struct seccompfs_inode *config;
			struct seccompfs_inode *begin;
			struct rb_root subdir;
		} root;
		struct {
			struct seccompfs_inode *log;
			struct rb_node dir_node;
			unsigned long counting;
		} pid;
		struct {
			struct list_head filter_entry_head;
		} config;
		struct {
			struct seccompfs_inode *root;
			unsigned long counting;
		} begin;
		struct {
			int x;
		} log;
	} type;
	struct inode vfs_inode;
};

static inline struct seccompfs_inode *SECCOMP_I(const struct inode *inode)
{
	return container_of(inode, struct seccompfs_inode, vfs_inode);
}

struct inode *seccompfs_get_inode(struct super_block *sb,
	struct inode *parent, pid_t pid, enum seccompfs_inode_type type);
