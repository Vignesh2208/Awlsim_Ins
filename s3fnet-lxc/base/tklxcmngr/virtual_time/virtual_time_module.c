#include "virtual_time_module.h"

// Proc file declarations
static struct proc_dir_entry *dilation_dir;
static struct proc_dir_entry *dilation_file;
hashmap lxcs;
llist lxc_list;

struct awlsim_gettime_struct{

	char buf[100];
	long pid;
};

struct task_struct* find_task_by_pid(unsigned int nr)
{
        struct task_struct* task;
        rcu_read_lock();
        task=pid_task(find_vpid(nr), PIDTYPE_PID);
        rcu_read_unlock();
        return task;
}

void get_dilated_time(struct task_struct * task,struct timeval* tv)
{
	s64 temp_past_physical_time;

	do_gettimeofday(tv);

	if(task->virt_start_time != 0){
		if (task->group_leader != task) { //use virtual time of the leader thread
                       	task = task->group_leader;
        }
		s64 now = timeval_to_ns(tv);
		s32 rem;
		s64 real_running_time;
		s64 dilated_running_time;
		//spin_lock(&task->dialation_lock);
		if(task->freeze_time == 0){
			real_running_time = now - task->virt_start_time;
		}
		else{
			real_running_time = task->freeze_time - task->virt_start_time;
		}
		//real_running_time = now - task->virt_start_time;
		//if (task->freeze_time != 0)
		//	temp_past_physical_time = task->past_physical_time + (now - task->freeze_time);
		//else
		temp_past_physical_time = task->past_physical_time;

		if (task->dilation_factor > 0) {
			dilated_running_time = div_s64_rem( (real_running_time - temp_past_physical_time)*1000 ,task->dilation_factor,&rem) + task->past_virtual_time;
			now = dilated_running_time + task->virt_start_time;
		}
		else if (task->dilation_factor < 0) {
			dilated_running_time = div_s64_rem( (real_running_time - temp_past_physical_time)*(task->dilation_factor*-1),1000,&rem) + task->past_virtual_time;
			now =  dilated_running_time + task->virt_start_time;
		}
		else {
			dilated_running_time = (real_running_time - temp_past_physical_time) + task->past_virtual_time;
			now = dilated_running_time + task->virt_start_time;
		}
		
		if(task->freeze_time == 0){
			task->past_physical_time = real_running_time;
			task->past_virtual_time = dilated_running_time;
		}
		//spin_unlock(&task->dialation_lock);
		*tv = ns_to_timeval(now);
	}

	return;

}


/***
This handles how a process from userland communicates with the kernel module. The process basically writes to:
/proc/dilation/status with a command ie, 'W', which will tell the kernel module to call the sec_clean_exp() function
***/
ssize_t status_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{
	char write_buffer[STATUS_MAXSIZE];
	int lxcName_pos = -1;
	int n_insns_pos = -1;
	int frac_insns_pos = -1;
	char * writer_name;
	char * lxcName;
	char * n_insns_curr_rnd;
	char * frac_insns_curr_rnd;
	lxc_virtual_time_elem * lxc = NULL;

	s64 n_insns_curr_round;
	s64 frac_insns_curr_round;


	unsigned long buffer_size;
	int i = 0;
	int ret = 0;
	unsigned long flags;

 	if(count > STATUS_MAXSIZE)
	{
    		buffer_size = STATUS_MAXSIZE;
  	}
	else
	{
		buffer_size = count;

	}

	for(i = 0; i < STATUS_MAXSIZE; i++)
		write_buffer[i] = '\0';

  	if(copy_from_user(write_buffer, buffer, buffer_size))
	{
	    return -EFAULT;
	}

	for(i = 0; i < STATUS_MAXSIZE; i++){
		if(lxcName_pos == -1){
			if(write_buffer[i] == ','){
				write_buffer[i] = '\0';
				lxcName_pos = i + 1;
			}

		}
		else if(n_insns_pos == -1){
			if(write_buffer[i] == ','){
				write_buffer[i] = '\0';
				n_insns_pos = i + 1;
			}
		}
		else if(frac_insns_pos == -1){
			if(write_buffer[i] == ','){
				write_buffer[i] = '\0';
				frac_insns_pos = i + 1;
			}

		}
		else if(write_buffer[i] == ','){
				write_buffer[i] = '\0';
				break;
			}
	}

	if(lxcName_pos == -1 || n_insns_pos == -1 || frac_insns_pos == -1){
		printk(KERN_INFO "Awlsim : Error: Incorrect write format\n");
		return -1;
	}

	writer_name = write_buffer;
	lxcName = write_buffer + lxcName_pos;
	n_insns_curr_rnd = write_buffer + n_insns_pos;
	frac_insns_curr_rnd = write_buffer + frac_insns_pos;

	n_insns_curr_round = atoi(n_insns_curr_rnd);
	frac_insns_curr_round = atoi(frac_insns_curr_rnd);

	lxc = hmap_get(&lxcs,lxcName);
	
	/*if(lxc == NULL){
		lxc = kmalloc(sizeof(struct lxc_virtual_time_element),GFP_KERNEL);
		if(!lxc)
			return -1;

		for(i = 0; i < 100; i++)
			lxc->lxcName[i] = '\0';
		strcpy(lxc->lxcName,lxcName);
		spin_lock_init(&lxc->lxc_entry_lock);
		lxc->n_instructions_already_executed = 0;
		lxc->fraction_instructions_executed = 0;
		lxc->n_instructions_in_nxt_round = 0;
		lxc->virt_start_time_set = 0;
		lxc->virt_start_time = 0;
		hmap_put(&lxcs,lxc->lxcName,lxc);
		llist_append(&lxc_list,lxc->lxcName);

	}*/

	if(lxc != NULL){

		spin_lock_irqsave(&lxc->lxc_entry_lock,flags);
		if(strcmp(writer_name,"Awlsim") == 0){ // written by awlsim running inside lxc
			if(!lxc->virt_start_time_set){
				if(current->virt_start_time > 0){
					lxc->virt_start_time = current->virt_start_time;
					lxc->virt_start_time_set = 1;
				}
			}
			if(n_insns_curr_round > 0){
				lxc->n_instructions_already_executed += n_insns_curr_round;
				lxc->n_instructions_in_nxt_round = lxc->n_instructions_in_nxt_round - n_insns_curr_round;
				if(lxc->n_instructions_in_nxt_round <= 0)
					lxc->n_instructions_in_nxt_round = 0;
				if(frac_insns_curr_round < 1000 && frac_insns_curr_round >= 0)
					lxc->fraction_instructions_executed = frac_insns_curr_round;
				else{
					lxc->fraction_instructions_executed = 0;
					printk(KERN_INFO "Awlsim : Error: frac_insns_curr_round must be >= 0 and < 1000\n");
				}

				//printk(KERN_INFO "Awlsim : Write by Awlsim LXC %s : n_insns_in_nxt_round = %lu, fract_insns_executed = %lu, n_instructions_already_executed = %lu\n",lxcName,lxc->n_instructions_in_nxt_round, lxc->fraction_instructions_executed,lxc->n_instructions_already_executed);
			}
			else{
				printk(KERN_INFO "Awlsim: Error: n_insns_curr_round must be > 0\n");
			}
		}
		else{	// written by s3fnet
				lxc->n_instructions_in_nxt_round += n_insns_curr_round;
				lxc->fraction_instructions_executed += frac_insns_curr_round;

				if(lxc->fraction_instructions_executed > 1000){
					lxc->n_instructions_in_nxt_round += 1;
					lxc->fraction_instructions_executed = lxc->fraction_instructions_executed - 1000;
				}

				//printk(KERN_INFO "Awlsim : Write by S3F for LXC %s : n_insns_in_nxt_round = %lu, fract_insns_executed = %lu, n_instructions_already_executed = %lu\n",lxcName,lxc->n_instructions_in_nxt_round, lxc->fraction_instructions_executed,lxc->n_instructions_already_executed);

		}
		spin_unlock_irqrestore(&lxc->lxc_entry_lock,flags);


	}
	

	return count;


}



/***
This function gets executed when the kernel module is loaded. It creates the file for process -> kernel module communication,
sets up mutexes, timers, and hooks the system call table.
***/
int __init my_module_init(void)
{
	int i;

   	printk(KERN_INFO "Awlsim: Virtual Time MODULE\n");

	//Set up TimeKeeper status file in /proc
  	dilation_dir = proc_mkdir(DILATION_DIR, NULL);
  	if(dilation_dir == NULL)
	{
	    remove_proc_entry(DILATION_DIR, NULL);
   		printk(KERN_INFO "Awlsim: Error: Could not initialize /proc/%s\n", DILATION_DIR);
   		return -ENOMEM;
  	}
  	printk(KERN_INFO "Awlsim: /proc/%s created\n", DILATION_DIR);
	dilation_file = proc_create(DILATION_FILE, 0660, dilation_dir,&proc_file_fops);
	if(dilation_file == NULL)
	{
	    remove_proc_entry(DILATION_FILE, dilation_dir);
   		printk(KERN_ALERT "Error: Could not initialize /proc/%s/%s\n", DILATION_DIR, DILATION_FILE);
   		return -ENOMEM;
  	}
	printk(KERN_INFO "Awlsim: /proc/%s/%s created\n", DILATION_DIR, DILATION_FILE);

	hmap_init( &lxcs,"string",0);
	llist_init(&lxc_list);

  	return 0;
}

/***
This function gets called when the kernel module is unloaded. It frees up all memory, deletes timers, and fixes
the system call table.
***/
void __exit my_module_exit(void)
{
	int i;
	char * next_lxcName = NULL;
	struct lxc_virtual_time_element * lxc = NULL;	

	remove_proc_entry(DILATION_FILE, dilation_dir);
   	printk(KERN_INFO "Awlsim: /proc/%s/%s deleted\n", DILATION_DIR, DILATION_FILE);
   	remove_proc_entry(DILATION_DIR, NULL);
   	printk(KERN_INFO "Awlsim: /proc/%s deleted\n", DILATION_DIR);

	

   	while(llist_size(&lxc_list) > 0){
		next_lxcName = llist_pop(&lxc_list);
		if(next_lxcName != NULL){
			printk(KERN_INFO "Awlsim::cleanup() at lxc = %s\n",next_lxcName);
			lxc = hmap_get(&lxcs,next_lxcName);					
			if(lxc != NULL){
				hmap_remove(&lxcs,lxc->lxcName);
				kfree(lxc);	
			}
		}				
	}

						
	hmap_destroy(&lxcs);
	llist_destroy(&lxc_list);
	

	printk(KERN_INFO "Awlsim: Virtual Time MODULE UNLOADED\n");
}

int vttime_open(struct inode *inode, struct file *filp){

	char lxcName[KERNEL_BUF_SIZE];
	lxc_virtual_time_elem * lxc = NULL;
	int i;
	unsigned long flags;

	for(i = 0; i < KERNEL_BUF_SIZE; i++)
			lxcName[i] = '\0';
	get_lxc_name(current,lxcName);

	if(strcmp(lxcName,"NA") != 0){

		lxc = hmap_get(&lxcs,lxcName);
		if(lxc == NULL){
			lxc = kmalloc(sizeof(struct lxc_virtual_time_element),GFP_KERNEL);
			if(lxc == NULL)
				return 0;

			for(i = 0; i < 100; i++)
				lxc->lxcName[i] = '\0';
			strcpy(lxc->lxcName,lxcName);
			spin_lock_init(&lxc->lxc_entry_lock);
			lxc->n_instructions_already_executed = 0;
			lxc->fraction_instructions_executed = 0;
			lxc->n_instructions_in_nxt_round = 0;
			lxc->virt_start_time = current->virt_start_time;
			lxc->virt_start_time_set = 1;
			llist_append(&lxc_list,lxc->lxcName);
			hmap_put(&lxcs,lxc->lxcName,lxc);				
			
		}
		else{
			spin_lock_irqsave(&lxc->lxc_entry_lock,flags);
			if(lxc->virt_start_time_set == 0){
			lxc->virt_start_time = current->virt_start_time;
			lxc->virt_start_time_set = 1;
			}
			spin_unlock_irqrestore(&lxc->lxc_entry_lock,flags);
		}

	}


	return 0;
}

//returns current virtual time, number of insns in current round if read by an Awlsim process inside lxc. S3fnet does not use this to get virtual
// time. S3FNet will use an ioctl to get virtual time and n_insns_left in curr round 
ssize_t status_read(struct file *pfil, char __user *pBuf, size_t len, loff_t *p_off)
{

		char lxcName[KERNEL_BUF_SIZE];
		char temp_read_buf[2*KERNEL_BUF_SIZE];


		int i = 0;
		static int finished = 0;
		if ( finished ) {
			//printk(KERN_INFO "Awlsim : Vttime: Proc file read: END\n");
			finished = 0;
			return 0;
		}
		finished = 1;

		lxc_virtual_time_elem * lxc = NULL;
		unsigned long flags;
		s64 virt_time = 0;
		s64 now = 0;
		s64 virt_running_time = 0;
		s32 rem;
		s64 n_insn_curr_round = 0;
		s64 frac_insns_curr_round = 0;
		struct timeval tv;
		int buffer_size = 0;
		
		if(len < 2*KERNEL_BUF_SIZE){
			printk(KERN_INFO "Awlsim: Error: Not enough space in read buf\n");
			return 0;
		}

		for(i = 0; i < KERNEL_BUF_SIZE; i++)
			lxcName[i] = '\0';
		//do_gettimeofday(&tv);
		get_dilated_time(current,&tv);
		now = timeval_to_ns(&tv);

		flush_buffer(lxcName,KERNEL_BUF_SIZE);		
		flush_buffer(temp_read_buf,2*KERNEL_BUF_SIZE);
		get_lxc_name(current,lxcName);


		if(strcmp(lxcName,"NA") != 0){

			lxc = hmap_get(&lxcs,lxcName);
			if(lxc != NULL){
				
				spin_lock_irqsave(&lxc->lxc_entry_lock,flags);
				printk(KERN_INFO "Awlsim: Read by LXC %s : n_insns_in_nxt_round = %llu, n_instructions_already_executed = %llu\n",lxcName,lxc->n_instructions_in_nxt_round,lxc->n_instructions_already_executed);
				if(lxc->virt_start_time_set){
					virt_running_time = lxc->n_instructions_already_executed*PER_INSN_DURATION + div_s64_rem(lxc->fraction_instructions_executed*PER_INSN_DURATION,1000,&rem);
					now = lxc->virt_start_time + virt_running_time;
				}
				n_insn_curr_round = lxc->n_instructions_in_nxt_round;
				spin_unlock_irqrestore(&lxc->lxc_entry_lock,flags);

			}
			else{

				if(current->virt_start_time > 0)
					now = current->virt_start_time;
			}

		}

		tv = ns_to_timeval(now);
		sprintf(temp_read_buf,"%lu\n%lu\n%lu\n",tv.tv_sec,tv.tv_usec,n_insn_curr_round);
		i = 0;
		while(temp_read_buf[i] != NULL)
			i++;
		buffer_size = i;
		if(buffer_size > 0 && buffer_size < 2*KERNEL_BUF_SIZE){
			if (copy_to_user(pBuf, temp_read_buf, buffer_size) ) {
				return -EFAULT;
			}
			return buffer_size;
		}
		else{
			return 0;
		}

        return 0;
}

long virt_time_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

	int err = 0, tmp;
	int retval = 0;
	int i = 0;
	uint8_t mask = 0;
	unsigned long flags;
	char * arg_lxcName = NULL;
	char tmp_lxcName[KERNEL_BUF_SIZE];
	s64 virt_time = 0;
	s64 now = 0;
	s64 virt_running_time = 0;
	s32 rem;
	struct timeval tv;
	s64 n_insn_curr_round;
	lxc_virtual_time_elem * lxc = NULL;
	struct awlsim_gettime_struct * gettime;
	unsigned int pid;


	flush_buffer(tmp_lxcName,KERNEL_BUF_SIZE);

	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != AWLSIM_VIRT_TIME_IOC_MAGIC) return -ENOTTY;
	
	/*
	 * the direction is a bitmask, and VERIFY_WRITE catches R/W
	 * transfers. `Type' is user-oriented, while
	 * access_ok is kernel-oriented, so the concept of "read" and
	 * "write" is reversed
	 */
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));

	if (err) return -EFAULT;

	switch(cmd) {

		case AWLSIM_VIRT_TIME_GETTIME 	:	gettime = (struct awlsim_gettime_struct *)arg;
											pid = gettime->pid;
											struct task_struct * tsk;
											tsk = find_task_by_pid(pid);

											arg_lxcName = (char *)gettime->buf;
											if(tsk != NULL){

												if(tsk->virt_start_time > 0)
													now = tsk->virt_start_time;											
												else{
													get_dilated_time(tsk,&tv);
													now = timeval_to_ns(&tv);	
												}
											}
											else{
												printk(KERN_INFO "Awlsim: Tsk does not exist %d\n",pid);
												do_gettimeofday(&tv);
												now = timeval_to_ns(&tv);		
											}
											
											if(arg_lxcName != NULL){

												if(copy_from_user(tmp_lxcName,arg_lxcName,strlen(arg_lxcName)))
												{
													printk(KERN_INFO "Awlsim: ioctl error: copy from user\n");
													return -EFAULT;		
												}

												lxc = hmap_get(&lxcs,tmp_lxcName);
												if(lxc != NULL){
													
													spin_lock_irqsave(&lxc->lxc_entry_lock,flags);
													printk(KERN_INFO "Awlsim: Read by S3F for LXC %s : n_insns_in_nxt_round = %llu, n_instructions_already_executed = %llu\n",tmp_lxcName,lxc->n_instructions_in_nxt_round, lxc->n_instructions_already_executed);
													if(lxc->virt_start_time_set){
														virt_running_time = lxc->n_instructions_already_executed*PER_INSN_DURATION + div_s64_rem(lxc->fraction_instructions_executed*PER_INSN_DURATION,1000,&rem);
														now = lxc->virt_start_time + virt_running_time;
													}													
													spin_unlock_irqrestore(&lxc->lxc_entry_lock,flags);

												}
												else{
													printk(KERN_INFO "Awlsim: Read by S3F for LXC %s not found\n",tmp_lxcName);
												}											
												tv = ns_to_timeval(now);
												flush_buffer(tmp_lxcName,KERNEL_BUF_SIZE);
												sprintf(tmp_lxcName,"%lu\n%lu\n",tv.tv_sec,tv.tv_usec);
												if(copy_to_user(arg_lxcName, tmp_lxcName, KERNEL_BUF_SIZE)){

														printk(KERN_INFO "Awlsim: ioctl error: copy to user\n");
														return -EFAULT;
												}												
												return 0;

											}
											else{
												printk(KERN_INFO "Awlsim: ioctl error: lxc entry not found\n");
												return -EFAULT;
											}

											break;
												

		case AWLSIM_VIRT_TIME_GETSTATUS :	arg_lxcName = (char *)arg;
											if(arg_lxcName != NULL)
											{
												if(copy_from_user(tmp_lxcName,arg_lxcName,strlen(arg_lxcName)))
												{
													return -EFAULT;		
												}

												lxc = hmap_get(&lxcs,tmp_lxcName);
												if(lxc != NULL){
													spin_lock_irqsave(&lxc->lxc_entry_lock,flags);
													n_insn_curr_round = lxc->n_instructions_in_nxt_round;
													spin_unlock_irqrestore(&lxc->lxc_entry_lock,flags);

													if(n_insn_curr_round <= 0)
														return 0; // SUCCESS
													else
														return 1; // NOT DONE YET

												}

												return -EFAULT;											

											}
											else
												return -EFAULT;

											break;
		default				 :		return -ENOTTY;
	}

	return -EFAULT;

}

// Register the init and exit functions here so insmod can run them
module_init(my_module_init);
module_exit(my_module_exit);

// Required by kernel
MODULE_LICENSE("GPL");
