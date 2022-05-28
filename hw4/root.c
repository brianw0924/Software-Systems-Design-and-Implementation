#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <uapi/linux/mount.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/sched/task.h>
#include "internal.h"


static DEFINE_RWLOCK(seccompfs_subdir_lock);
static DEFINE_SPINLOCK(seccompfs_filter_list_lock);
static DEFINE_MUTEX(seccompfs_filter_list_mutex);

////////////operator////////////

static struct seccompfs_inode *seccompfs_search_pid(
			struct seccompfs_inode *seccompfs_root, unsigned pid)
{
	struct inode *inode;
	struct seccompfs_inode *curr;
	struct rb_node *temp = seccompfs_root->type.root.subdir.rb_node;

	while (temp) {
		curr = container_of(temp, struct seccompfs_inode, type.pid.dir_node);
		inode = &curr->vfs_inode;
		if (pid > inode->i_ino)
			temp = temp->rb_right;
		else if (pid < inode->i_ino)
			temp = temp->rb_left;
		else
			return curr;
	}

	return NULL;
}


static struct dentry *seccompfs_root_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct seccompfs_inode *seccomp_entry;
	struct seccompfs_inode *seccomp_root = SECCOMP_I(dir);
	char config[] = "config", begin[] = "begin";
	int config_len = strlen(config), begin_len = strlen(begin);


	if (config_len == dentry->d_name.len &&
			!memcmp(dentry->d_name.name, config, config_len))
		seccomp_entry = seccomp_root->type.root.config;
	else if (begin_len == dentry->d_name.len &&
			!memcmp(dentry->d_name.name, begin, begin_len))
		seccomp_entry = seccomp_root->type.root.begin;
	else {
		unsigned pid = pidstr_to_int(&dentry->d_name);
		if (pid == ~0U)
			return ERR_PTR(-ENOENT);
		read_lock(&seccompfs_subdir_lock);
		seccomp_entry = seccompfs_search_pid(seccomp_root, PID_INO(pid));
		read_unlock(&seccompfs_subdir_lock);
		if (!seccomp_entry)
			return ERR_PTR(-ENOENT);
	}

	return d_splice_alias(&seccomp_entry->vfs_inode, dentry);
}

static const struct inode_operations seccompfs_root_iops = {
	.lookup		= seccompfs_root_lookup,
	.getattr	= simple_getattr,
};

static inline struct seccompfs_inode *pid_subdir_first(
			struct seccompfs_inode *root)
{
	return rb_entry_safe(rb_first(&root->type.root.subdir),
		struct seccompfs_inode, type.pid.dir_node);
}

static inline struct seccompfs_inode *pid_subdir_next(
			struct seccompfs_inode *dir)
{
	return rb_entry_safe(rb_next(&dir->type.pid.dir_node),
		struct seccompfs_inode, type.pid.dir_node);
}

static int seccompfs_root_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct seccompfs_inode *seccompfs_node = SECCOMP_I(inode);
	int i, count;
	char pid_name[12];

	if (!dir_emit_dots(file, ctx))
		return 0;

	if (ctx->pos == 2) {
		if (!dir_emit(ctx, "begin", 5, BEGIN_INO, DT_REG))
			return 0;
		ctx->pos = 3;
	}
	if (ctx->pos == 3) {
		if (!dir_emit(ctx, "config", 6, CONFIG_INO, DT_REG))
			return 0;
		ctx->pos = 4;
	}

	i = ctx->pos - 4;

	read_lock(&seccompfs_subdir_lock);
	seccompfs_node = pid_subdir_first(seccompfs_node);

	for (;;) {
		if (!seccompfs_node) {
			read_unlock(&seccompfs_subdir_lock);
			return 0;
		}
		if (!i)
			break;
		seccompfs_node = pid_subdir_next(seccompfs_node);
		i--;
	}

	do {
		//struct seccompfs_inode *next;
		read_unlock(&seccompfs_subdir_lock);
		inode = &seccompfs_node->vfs_inode;
		count = snprintf(pid_name, 12, "%lu", INO_TO_PID(inode->i_ino));
		if (!dir_emit(ctx, pid_name, count,
			    inode->i_ino, DT_DIR)) {
			return 0;
		}
		ctx->pos++;
		read_lock(&seccompfs_subdir_lock);
		//next = pid_subdir_next(seccompfs_node);
		//seccompfs_node = next;
		seccompfs_node = pid_subdir_next(seccompfs_node);
	} while (seccompfs_node);
	read_unlock(&seccompfs_subdir_lock);
	return 1;
}

static const struct file_operations seccompfs_root_fops = {
	.read			= generic_read_dir,
	.iterate_shared		= seccompfs_root_readdir,
	.llseek			= generic_file_llseek,
};

static struct dentry *seccompfs_pid_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct seccompfs_inode *seccomp_entry;
	struct seccompfs_inode *seccomp_root = SECCOMP_I(dir);
	char log[] = "log";
	int log_len = strlen(log);


	if (log_len == dentry->d_name.len &&
			!memcmp(dentry->d_name.name, log, log_len))
		seccomp_entry = seccomp_root->type.pid.log;
	else
		return NULL;

	return d_splice_alias(&seccomp_entry->vfs_inode, dentry);
}

static const struct inode_operations seccompfs_pid_iops = {
	.lookup		= seccompfs_pid_lookup,
	.getattr	= simple_getattr,
};


static int seccompfs_pid_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);

	if (!dir_emit_dots(file, ctx))
		return 0;
	if (ctx->pos == 2) {
		if (!dir_emit(ctx, "log", 3, PIDINO_TO_LOGINO(inode->i_ino), DT_REG))
			return 0;
		ctx->pos = 3;
	}
	return 1;
}

static const struct file_operations seccompfs_pid_fops = {
	.read			= generic_read_dir,
	.iterate_shared		= seccompfs_pid_readdir,
	.llseek			= generic_file_llseek,
};

static const struct inode_operations seccompfs_config_iops = {
	.getattr	= simple_getattr,
};


static int fill_seccomp_filter_entry(char *buf,
		struct seccompfs_filter_entry **entry)
{
	char *token;
	unsigned int pid;
	unsigned int ret;
	int i, len = 0;

	*entry = NULL;

	for (i = 0; (token = strsep(&buf, ",")); ++i) {
		if (kstrtouint(token, 10, &ret))
			goto incorrect_format;

		if (i == 0)
			pid = ret;
		else if (i == 1) {
			len = ret;

			if (len == 0)
				goto incorrect_format;

			*entry = kmalloc(len * sizeof(unsigned short) 
				+ sizeof(struct seccompfs_filter_entry), GFP_KERNEL);

			if (!*entry)
				return -ENOMEM;
			(*entry)->pid = pid;
			(*entry)->len = len;
		}
		else if (ret >= __NR_syscalls || len == (i - 2))
			goto incorrect_format_free_ent;
		else
			(*entry)->syscall_no[i - 2] = ret;
	}

	if (i < 2)
		goto incorrect_format;

	if (i == 2 || i != (len + 2))
		goto incorrect_format_free_ent;

	return 0;

incorrect_format_free_ent:
	kfree(*entry);
incorrect_format:
	pr_info("seccompfs : config input format error\n");
	return -EINVAL;
}

static ssize_t seccompfs_config_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct seccompfs_inode *seccompfs_config = SECCOMP_I(inode);
	struct seccompfs_filter_entry *entry;
	char *ker_buf;
	int ret;

	ker_buf = kmalloc(len + 1, GFP_KERNEL);

	if (!ker_buf)
		return -ENOMEM;

	if (copy_from_user(ker_buf, buf, len)) {
		kfree(ker_buf);
		return -EFAULT;
	}

	ker_buf[len] = '\0';

	ret = fill_seccomp_filter_entry(ker_buf, &entry);
	kfree(ker_buf);

	if (ret)
		return ret;

	spin_lock(&seccompfs_filter_list_lock);
	list_add(&entry->entry_node, 
		&seccompfs_config->type.config.filter_entry_head);
	spin_unlock(&seccompfs_filter_list_lock);

	return len;
}

static const struct file_operations seccompfs_config_fops = {
	.write		= seccompfs_config_write,
	.open		= generic_file_open,
};

static const struct inode_operations seccompfs_begin_iops = {
	.getattr	= simple_getattr,
};

struct seccompfs_inode *seccompfs_insert_pid(struct seccompfs_inode *seccompfs_root, 
			pid_t pid, unsigned long counting)
{
	struct inode *inode = &seccompfs_root->vfs_inode;
	struct seccompfs_inode *curr;
	struct rb_node **temp, *parent;
	struct rb_root *tree = &seccompfs_root->type.root.subdir;

	temp = &tree->rb_node;
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct seccompfs_inode, type.pid.dir_node);
		inode = &curr->vfs_inode;
		parent = *temp;

		if (pid < inode->i_ino)
			temp = &((*temp)->rb_left);
		else if (pid > inode->i_ino)
			temp = &((*temp)->rb_right);
		else if (counting == curr->type.pid.counting)
			return curr;
		else {
			pr_info("seccompfs : pid %u has been attached filter, don't re attach\n", INO_TO_PID(pid));
			return curr;
		}
	}

	inode = seccompfs_get_inode(
			inode->i_sb, &seccompfs_root->vfs_inode, INO_TO_PID(pid), PID);
	if (!inode)
		return NULL;

	curr = SECCOMP_I(inode);

	curr->type.pid.counting = counting;

	rb_link_node(&curr->type.pid.dir_node, parent, temp);
	rb_insert_color(&curr->type.pid.dir_node, tree);

	return curr;
}

static ssize_t seccompfs_begin_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct seccompfs_inode *seccompfs_begin = SECCOMP_I(inode);
	struct seccompfs_inode *seccompfs_root = seccompfs_begin->type.begin.root;
	struct seccompfs_inode *seccompfs_config = 
				seccompfs_root->type.root.config;
	struct seccompfs_inode *seccompfs_pid;
	struct list_head *entry_head = 
		&seccompfs_config->type.config.filter_entry_head;
	LIST_HEAD(migrate_list);
	struct task_struct *target;
	struct seccompfs_filter_entry *entry, *next_entry;
	unsigned long counting = 0;

	inode_lock(inode);

	spin_lock(&seccompfs_filter_list_lock);
	if (!list_empty(entry_head)) {
		seccompfs_begin->type.begin.counting += 1;
		counting = seccompfs_begin->type.begin.counting;
		list_cut_position(&migrate_list, entry_head, entry_head->prev);//list_splice(entry_head, &migrate_list);
	}
	spin_unlock(&seccompfs_filter_list_lock);


	list_for_each_entry_safe(entry, next_entry, &migrate_list, entry_node) {
		rcu_read_lock();
		target = find_task_by_vpid(entry->pid);
		if (!target) {
			rcu_read_unlock();
			pr_info("seccompfs : pid %u cannot attach filter\n", entry->pid);
			goto remove_entry;
		}
		get_task_struct(target);
		rcu_read_unlock();
		write_lock(&seccompfs_subdir_lock);
		seccompfs_pid = seccompfs_insert_pid(seccompfs_root, 
				PID_INO(entry->pid), counting);
		write_unlock(&seccompfs_subdir_lock);
		put_task_struct(target);

		if (!seccompfs_pid) {
			spin_lock(&seccompfs_filter_list_lock);
			list_splice(&migrate_list, entry_head);//list_splice(&entry->entry_node, entry_head);
			spin_unlock(&seccompfs_filter_list_lock);
			inode_unlock(inode);
			return -ENOMEM;
		}
remove_entry:
		list_del(&entry->entry_node);
		kfree(entry);
	}

	inode_unlock(inode);

	return len;
}

static const struct file_operations seccompfs_begin_fops = {
	.write		= seccompfs_begin_write,
	.open		= generic_file_open,
};

static const struct inode_operations seccompfs_log_iops;


static const struct file_operations seccompfs_log_fops;


/////////////inode//////////////

static struct kmem_cache *seccompfs_inode_cachep;

static struct inode *seccompfs_alloc_inode(struct super_block *sb)
{
	struct seccompfs_inode *ei;

	ei = kmem_cache_alloc(seccompfs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}


static void seccompfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}

static void seccompfs_free_inode(struct inode *inode)
{
	kmem_cache_free(seccompfs_inode_cachep, SECCOMP_I(inode));
}

static int seccompfs_drop_inode(struct inode *inode)
{
	return false;
}

const struct super_operations seccompfs_sops = {
	.alloc_inode	= seccompfs_alloc_inode,
	.free_inode	= seccompfs_free_inode,
	.drop_inode	= seccompfs_drop_inode,
	.evict_inode	= seccompfs_evict_inode,
	.statfs		= simple_statfs,
};

static struct inode *seccompfs_fill_root_inode(struct inode *inode)
{
	struct seccompfs_inode *seccomp_inode = SECCOMP_I(inode);
	struct inode *child_inode;

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_ino = ROOT_INO;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO;
	i_uid_write(inode, from_kuid(&init_user_ns, current_fsuid()));
	i_gid_write(inode, from_kgid(&init_user_ns, current_fsgid()));
	//inode->i_uid = from_kuid(&init_user_ns, current_fsuid());
	//inode->i_gid = from_kgid(&init_user_ns, current_fsgid());
	set_nlink(inode, 4);  // . .. begin config
	inode->i_op = &seccompfs_root_iops;
	inode->i_fop = &seccompfs_root_fops;

	child_inode = seccompfs_get_inode(inode->i_sb, inode, 0, BEGIN);
	if (!child_inode) {
		kmem_cache_free(seccompfs_inode_cachep, SECCOMP_I(child_inode));
		return NULL;
	}
	seccomp_inode->type.root.begin = SECCOMP_I(child_inode);
	child_inode = seccompfs_get_inode(inode->i_sb, inode, 0, CONFIG);
	if (!child_inode) {
		kmem_cache_free(seccompfs_inode_cachep, seccomp_inode->type.root.begin);
		kmem_cache_free(seccompfs_inode_cachep, seccomp_inode);
		return NULL;
	}
	seccomp_inode->type.root.config = SECCOMP_I(child_inode);
	seccomp_inode->type.root.subdir = RB_ROOT;

	return inode;
}

static struct inode *seccompfs_fill_config_inode(struct inode *inode,
		struct inode *parent)
{
	struct seccompfs_inode *seccomp_inode = SECCOMP_I(inode);

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_ino = CONFIG_INO;
	inode->i_mode = S_IFREG | S_IWUSR;
	inode->i_uid = parent->i_uid;
	inode->i_gid = parent->i_gid;
	inode->i_op = &seccompfs_config_iops;
	inode->i_fop = &seccompfs_config_fops;

	INIT_LIST_HEAD(&seccomp_inode->type.config.filter_entry_head);

	return inode;
}

static struct inode *seccompfs_fill_begin_inode(struct inode *inode,
		struct inode *parent)
{
	struct seccompfs_inode *seccomp_inode = SECCOMP_I(inode);
	struct seccompfs_inode *seccomp_root = SECCOMP_I(parent);

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_ino = BEGIN_INO;
	inode->i_mode = S_IFREG | S_IWUSR;
	inode->i_uid = parent->i_uid;
	inode->i_gid = parent->i_gid;
	inode->i_op = &seccompfs_begin_iops;
	inode->i_fop = &seccompfs_begin_fops;

	seccomp_inode->type.begin.root = seccomp_root;
	seccomp_inode->type.begin.counting = 0;

	return inode;
}

static struct inode *seccompfs_fill_pid_inode(struct inode *inode,
		struct inode *parent, pid_t pid)
{
	struct seccompfs_inode *seccomp_inode = SECCOMP_I(inode);
	struct inode *child_inode;

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_ino = PID_INO(pid);
	inode->i_mode = S_IFDIR | S_IRUSR | S_IXUSR;
	inode->i_uid = parent->i_uid;
	inode->i_gid = parent->i_gid;
	set_nlink(inode, 3);  // . .. log
	inode->i_op = &seccompfs_pid_iops;
	inode->i_fop = &seccompfs_pid_fops;

	child_inode = seccompfs_get_inode(inode->i_sb, inode, pid, LOG);

	if (!child_inode) {
		kmem_cache_free(seccompfs_inode_cachep, seccomp_inode);
		return NULL;
	}

	seccomp_inode->type.pid.log = SECCOMP_I(child_inode);

	return inode;
}

static struct inode *seccompfs_fill_log_inode(struct inode *inode,
		struct inode *parent, pid_t pid)
{
	//struct seccompfs_inode *seccomp_inode = SECCOMP_I(inode);

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_ino = LOG_INO(pid);
	inode->i_mode = S_IFREG | S_IRUSR;
	inode->i_uid = parent->i_uid;
	inode->i_gid = parent->i_gid;
	inode->i_op = &seccompfs_log_iops;
	inode->i_fop = &seccompfs_log_fops;


	return inode;
}

struct inode *seccompfs_get_inode(struct super_block *sb,
		struct inode *parent, pid_t pid, enum seccompfs_inode_type type)
{
	struct inode *inode = new_inode_pseudo(sb);

	if (inode) {
		
		switch (type) {
		case ROOT:
			return seccompfs_fill_root_inode(inode);
		case CONFIG:
			return seccompfs_fill_config_inode(inode, parent);
		case BEGIN:
			return seccompfs_fill_begin_inode(inode, parent);
		case PID:
			return seccompfs_fill_pid_inode(inode, parent, pid);
		case LOG:
			return seccompfs_fill_log_inode(inode, parent, pid);
		default:
			kmem_cache_free(seccompfs_inode_cachep, SECCOMP_I(inode));
			pr_debug("seccompfs_get_inode : unknown type\n");
			return NULL;
		}

	}
	return inode;
}


static int seccompfs_fill_super(struct super_block *s, struct fs_context *fc)
{
	struct inode *root_inode;
	int ret = 0;


	/* User space would break if executables or devices appear on proc */
	s->s_iflags |= SB_I_USERNS_VISIBLE | SB_I_NOEXEC | SB_I_NODEV;
	s->s_flags |= SB_NODIRATIME | SB_NOSUID | SB_NOEXEC | SB_ACTIVE;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	//s->s_magic = PROC_SUPER_MAGIC;
	s->s_op = &seccompfs_sops;
	s->s_time_gran = 1;

	
	/* procfs dentries and inodes don't require IO to create */
	s->s_shrink.seeks = 0;

	
	root_inode = seccompfs_get_inode(s, NULL, 0, ROOT);
	if (!root_inode) {
		pr_err("seccompfs_fill_super: get root inode failed\n");
		return -ENOMEM;
	}

	s->s_root = d_make_root(root_inode);
	if (!s->s_root) {
		pr_err("seccompfs_fill_super: allocate dentry failed\n");
		return -ENOMEM;
	}

	return ret;
}

static int seccompfs_get_tree(struct fs_context *fc)
{
	return get_tree_keyed(fc, seccompfs_fill_super, NULL);
}


static const struct fs_context_operations seccompfs_fs_context_ops = {
	.get_tree	= seccompfs_get_tree,
};


static int seccompfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &seccompfs_fs_context_ops;
	return 0;
}



static struct file_system_type seccompfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "seccompfs",
	.init_fs_context	= seccompfs_init_fs_context,
	.kill_sb		= kill_litter_super,
	.fs_flags		= FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
};


static void init_once(void *foo)
{
	struct seccompfs_inode *ei = (struct seccompfs_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_seccompfs(void)
{
	int ret;
	struct vfsmount *mount;

	seccompfs_inode_cachep = kmem_cache_create("seccompfs_inode_cache",
			sizeof(struct seccompfs_inode),
			0, (SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD | SLAB_ACCOUNT |
			SLAB_PANIC),
			init_once);

	ret = register_filesystem(&seccompfs_fs_type);
	if (ret < 0)
		return ret;

	mount = kern_mount(&seccompfs_fs_type);
	if (IS_ERR(mount))
		return PTR_ERR(mount);

	return 0;
}
fs_initcall(init_seccompfs);
