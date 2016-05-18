#ifndef UTIL_HEADER_FILE
#define UTIL_HEADER_FILE


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <asm/siginfo.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/spinlock_types.h>
#include <linux/hashtable.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/cgroup.h>
//#include "utils/linkedlist.h"
//#include "utils/hashmap.h"
#include "linkedlist.h"
#include "hashmap.h"

#define KERNEL_BUF_SIZE 100
#define PER_INSN_DURATION 1000 // 10us

/* Use 'k' as magic number */
#define AWLSIM_VIRT_TIME_IOC_MAGIC  'l'

#define AWLSIM_VIRT_TIME_GETTIME _IOR(AWLSIM_VIRT_TIME_IOC_MAGIC,  1, int) // write to the rx buffer from user space. used by S3F simulator.
#define AWLSIM_VIRT_TIME_GETSTATUS _IOR(AWLSIM_VIRT_TIME_IOC_MAGIC,  2, int) // read the tx buffer into user space. used by S3F simulator.


s64 atoi(char *s);
void flush_buffer(char * buffer, int size);
char * extract_filename(char *str);
void get_lxc_name(struct task_struct * process, char * lxcName);

#endif