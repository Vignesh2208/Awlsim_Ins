#include "util.h"

s64 atoi(char *s)
{
        int i;
        s64 n;
        n = 0;
        for(i = 0; *(s+i) >= '0' && *(s+i) <= '9'; i++)
                n = 10*n + *(s+i) - '0';
        return n;
}


void flush_buffer(char * buffer, int size){
	int i = 0;
	for(i = 0; i < size; i++)
		buffer[i] = NULL;
	

}


char * extract_filename(char *str)
{
    int     ch = '/';
    char   *pdest;

 
    // Search backwards for last backslash in filepath 
    pdest = strrchr(str, ch);
     
    // if backslash not found in filepath
    if(pdest == NULL )
    {
        pdest = str;  // The whole name is a file in current path? 
    }
    else
    {
    	pdest++; // Skip the backslash itself.
    }
     
    // extract filename from file path
    return pdest;
}

void get_lxc_name(struct task_struct * process, char * lxcName){

	struct cgroup * cgrp;

	char buf[KERNEL_BUF_SIZE];
	struct cgroupfs_root *root;
	int retval = 0;
	char * name;
	
	
	
	cgrp = task_cgroup(process,1);
	if(cgrp != NULL){
		retval = cgroup_path(cgrp, buf, KERNEL_BUF_SIZE);
		
		if (retval < 0){
			strcpy(lxcName,"NA");
			return;
		}
		else{
			if(strcmp(buf,"/") == 0)
					;
		else{
				name = extract_filename(buf);
				strcpy(lxcName,name);
				return;	

			}
		}
	}
	else{
		//printk(KERN_INFO "Socket Hook : Task cgroup is NULL\n");
	}

	strcpy(lxcName,"NA");
	

}