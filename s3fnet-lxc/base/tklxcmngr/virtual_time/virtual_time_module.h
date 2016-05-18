#ifndef VTTIME_HEADER_FILE
#define VTTIME_HEADER_FILE

#define LINUX

#include "util.h"

// the callback functions for the TimeKeeper status file
ssize_t status_read(struct file *pfil, char __user *pBuf, size_t len, loff_t *p_off);
ssize_t status_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);
long virt_time_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
int vttime_open(struct inode *inode, struct file *filp);


static const struct file_operations proc_file_fops = {
 .read = status_read,
 .open = vttime_open,
 .unlocked_ioctl = virt_time_ioctl,
 .write = status_write,
};



typedef struct lxc_virtual_time_element{


	char lxcName[100];
	spinlock_t lxc_entry_lock;
	s64 n_instructions_already_executed;
	s64 fraction_instructions_executed;
	s64 n_instructions_in_nxt_round;
	s64 virt_start_time;
	int virt_start_time_set;	

}lxc_virtual_time_elem;





#define STATUS_MAXSIZE 1004
#define DILATION_DIR "awlsim"
#define DILATION_FILE "vt_time"
#define EXP_CPUS 6




#endif

