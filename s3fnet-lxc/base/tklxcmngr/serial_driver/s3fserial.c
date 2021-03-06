#include "s3fserial.h"		/* local definitions */

MODULE_AUTHOR("Vignesh Babu");
MODULE_LICENSE("Dual BSD/GPL");

int dev_major = 0 ;
#ifdef DEV_MAJOR
dev_major = DEV_MAJOR;
#endif
int dev_minor =   0;
int nr_devs = NR_SERIAL_DEVS;	/* number of bare scull devices */
struct dev_struct * devices = NULL;


struct file_operations dev_fops = {
	.owner =    THIS_MODULE,
	.llseek =   s3fserial_llseek,
	.read =     s3fserial_read,
	.write =    s3fserial_write,
	.poll = 	s3fserial_poll,
	.unlocked_ioctl = s3fserial_ioctl,
	.open =     s3fserial_open,
	.release =  s3fserial_release,
};

struct lxc_entry * get_lxc_entry(char * lxc_name, int conn_id){
	struct dev_struct * dev;
	struct lxc_entry * lxc = NULL;
	dev = &devices[conn_id];	
	//spin_lock(&dev->dev_lock);
	lxc = hmap_get(&devices[conn_id].lxcs,lxc_name);
	//spin_unlock(&dev->dev_lock);
	

	return lxc;

}

int write_lxc_rxbuf(struct lxc_entry * lxc, int conn_id, int num_bytes_to_write, char * src_buf){

	struct lxc_connection * conn = lxc->connection;
	uint32_t rx_start = 0;
	uint32_t num_rx_bytes = 0;
	int i = 0, num_copied = 0;
	unsigned long flags;
	if(!conn)
		return -EFAULT;

	spin_lock_irqsave(&conn->conn_lock,flags);
	
	num_rx_bytes = conn->num_received_bytes;
	rx_start = mod((conn->recv_start + num_rx_bytes), RX_BUF_SIZE);
	if(RX_BUF_SIZE - num_rx_bytes < num_bytes_to_write){
		spin_unlock_irqrestore(&conn->conn_lock,flags);
		return -EFAULT; // not enough space
	}

	while(num_copied < num_bytes_to_write){
		conn->rx_buf[mod(rx_start + num_copied, RX_BUF_SIZE)] = src_buf[num_copied];
		num_copied++;
	}

	//conn->recv_start = mod(rx_start + num_bytes_to_write, RX_BUF_SIZE);
	conn->num_received_bytes += num_bytes_to_write;
	spin_unlock_irqrestore(&conn->conn_lock,flags);
	return 0;



}

int read_lxc_txbuf(struct lxc_entry * lxc, int conn_id, char * dst_buf){

	struct lxc_connection * conn = lxc->connection;
	uint32_t tx_start = 0;
	uint32_t num_tx_bytes = 0;
	int i = 0, num_copied = 0;
	unsigned long flags;
	if(!conn)
		return -EFAULT;

	spin_lock_irqsave(&conn->conn_lock,flags);
	num_tx_bytes = conn->num_bytes_to_transmit;
	//printk(KERN_INFO "s3fserial:read_lxc_buf : num tx bytes = %d\n",num_tx_bytes);
	while(num_copied < num_tx_bytes){
		dst_buf[num_copied] = conn->tx_buf[num_copied];
		num_copied++;
	}
	flush_buffer(conn->tx_buf,TX_BUF_SIZE);
	conn->num_bytes_to_transmit = 0;
	spin_unlock_irqrestore(&conn->conn_lock,flags);

	return num_tx_bytes;
}

long s3fserial_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

	int err = 0, tmp;
	int retval = 0;
	struct ioctl_conn_param * ioctl_conn;
	struct ioctl_conn_param tmp_ioctl_conn;
    struct lxc_entry * lxc;
    struct dev_struct * dev;
    struct lxc_connection * conn;
    int i = 0;
	uint8_t mask = 0;
	unsigned long flags;
	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != S3FSERIAL_IOC_MAGIC) return -ENOTTY;
	
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

		case S3FSERIAL_IOWRX :
								ioctl_conn = (struct ioctl_conn_param *)arg;
								if(ioctl_conn == NULL)
									return -EFAULT;
								
								if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param))){
									//printk(KERN_INFO "s3fserial::ioctl():IOWRX : ERROR ioctl IOWRX copy from user\n");
									return -EFAULT;
								}

								if(tmp_ioctl_conn.conn_id >= 0 && tmp_ioctl_conn.conn_id < NR_SERIAL_DEVS)
									lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);
								else
									lxc = NULL;

								if(!lxc){
									//printk(KERN_INFO "s3fserial::ioctl():IOWRX : ERROR ioctl IOWRX lxc not found\n");
									return -EFAULT;
								}
								return write_lxc_rxbuf(lxc,tmp_ioctl_conn.conn_id,tmp_ioctl_conn.num_bytes_to_write,tmp_ioctl_conn.bytes_to_write);
								

		case S3FSERIAL_IORTX :  ioctl_conn = (struct ioctl_conn_param *)arg;
								if(ioctl_conn == NULL)
									return -EFAULT;

								if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param))){
									//printk(KERN_INFO "s3fserial::ioctl():IORTX : ERROR ioctl IORTX copy from user\n");
									return -EFAULT;
								}

								if(tmp_ioctl_conn.conn_id >= 0 && tmp_ioctl_conn.conn_id < NR_SERIAL_DEVS)
									lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);				
								else
									lxc = NULL;

								if(!lxc){
									//printk(KERN_INFO "s3fserial::ioctl():IORTX : ERROR ioctl IORTX lxc not found\n");
									return -EFAULT;
								}

								int ret = read_lxc_txbuf(lxc,tmp_ioctl_conn.conn_id,tmp_ioctl_conn.bytes_to_read);
								copy_to_user(&ioctl_conn->num_bytes_to_read,&ret,sizeof(int));
								if(ret)
									copy_to_user(ioctl_conn->bytes_to_read, tmp_ioctl_conn.bytes_to_read, ret);

								return ret;

		case S3FSERIAL_SETCONNLXC : ioctl_conn = (struct ioctl_conn_param *)arg;
									if(ioctl_conn == NULL)
										return -EFAULT;
									if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param)))
									{
										//printk(KERN_INFO "s3fserial::ioctl():SETCONNLXC : ERROR ioctl SETCONNLXC copy from user\n");
										return -EFAULT;		
									}	
									if(tmp_ioctl_conn.conn_id >= 0 && tmp_ioctl_conn.conn_id < NR_SERIAL_DEVS){
										//printk(KERN_INFO "s3fserial::ioctl():SETCONNLXC : owner lxc name : %s. Conn_id = %d\n",tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);
										lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);
									}
									else
										lxc = NULL;

									if(!lxc){
										//printk(KERN_INFO "s3fserial::ioctl():SETCONNLXC : ERROR ioctl SETCONNLXC lxc not found\n");
										return -EFAULT;
									}

									conn = lxc->connection;
									if(!conn){
										//printk(KERN_INFO "s3fserial::ioctl():SETCONNLXC : ERROR ioctl SETCONNLXC lxc-conn not found\n");
										return -EFAULT;
									}
									spin_lock(&conn->conn_lock);
									strncpy(conn->dst_lxc_name,tmp_ioctl_conn.dst_lxc_name,KERN_BUF_SIZE);
									conn->params_set = 1;
									spin_unlock(&conn->conn_lock);
									
									return 0;

		case S3FSERIAL_GETCONNLXC : ioctl_conn = (struct ioctl_conn_param *)arg;
									if(ioctl_conn == NULL)		
											return -EFAULT;
									if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param)))
									{
										//printk(KERN_INFO "s3fserial::ioctl():GETCONNLXC : ERROR ioctl GETCONNLXC copy from user\n");
										return -EFAULT;		
									}	
									if(tmp_ioctl_conn.conn_id >= 0 && tmp_ioctl_conn.conn_id < NR_SERIAL_DEVS)
										lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);
									else
										lxc = NULL;

									if(!lxc){
										//printk(KERN_INFO "s3fserial::ioctl():GETCONNLXC : ERROR ioctl GETCONNLXC lxc not found\n");
										return -EFAULT;
									}

									conn = lxc->connection;
									if(!conn){ // dst_lxc_name not set
										//printk(KERN_INFO "s3fserial::ioctl():GETCONNLXC : ERROR ioctl GETCONNLXC lxc-conn params not set\n");
										return -EFAULT;
									}

									spin_lock(&conn->conn_lock);
									if(conn->params_set == 1)
										strncpy(tmp_ioctl_conn.dst_lxc_name,conn->dst_lxc_name,KERN_BUF_SIZE);
									else{
										spin_unlock(&conn->conn_lock);
										return -EFAULT;
									}

									spin_unlock(&conn->conn_lock);

									if(copy_to_user(ioctl_conn->dst_lxc_name, tmp_ioctl_conn.dst_lxc_name, KERN_BUF_SIZE)){
										//printk(KERN_INFO "s3fserial::ioctl():GETCONNLXC : ERROR ioctl GETCONNLXC copy to user\n");
										return -EFAULT;
									}
									return 0;


		case S3FSERIAL_GETCONNID :  ioctl_conn = (struct ioctl_conn_param *)arg;
									if(ioctl_conn == NULL)
											return -EFAULT;
									if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param)))
									{
										//printk(KERN_INFO "s3fserial::ioctl():GETCONNID : ERROR ioctl GETCONNID copy from user\n");
										return -EFAULT;		
									}

									for(i = 0; i < NR_SERIAL_DEVS; i++){
										lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,i);
										if(lxc != NULL){
											conn = lxc->connection;
											if(conn != NULL){
												if(strcmp(tmp_ioctl_conn.dst_lxc_name,conn->dst_lxc_name) == 0){
													copy_to_user(&ioctl_conn->conn_id,&i, sizeof(int));
													return 0;
												}
											}
										}

									}

									return -EFAULT; // no such pair lxcs are connected.

		case S3FSERIAL_GETCONNSTATUS : 	ioctl_conn = (struct ioctl_conn_param *)arg;
										if(ioctl_conn == NULL)
											return -EFAULT;

										if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param)))
										{
											//printk(KERN_INFO "s3fserial::ioctl():GETCONNSTATUS : ERROR ioctl GETCONNID copy from user\n");
											return -EFAULT;		
										}

										
										lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,tmp_ioctl_conn.conn_id);
										if(lxc != NULL){
											conn = lxc->connection;
											if(conn != NULL){
												spin_lock(&conn->conn_lock);
												if(conn->params_set == 1){
													ioctl_conn->num_bytes_to_read = conn->num_received_bytes;
													ioctl_conn->num_bytes_to_write = conn->num_bytes_to_transmit;
													spin_unlock(&conn->conn_lock);
													if(copy_to_user(ioctl_conn->dst_lxc_name, conn->dst_lxc_name, KERN_BUF_SIZE)){
														
														//printk(KERN_INFO "s3fserial::ioctl():GETCONNSTATUS : ERROR ioctl GETCONNSTATUS copy to user\n");
														return -EFAULT;
													}
													//spin_unlock(&conn->conn_lock);
													return 0;
												}
												spin_unlock(&conn->conn_lock);
											}
										}
										
										
										return -EFAULT;

		// returns all connections which have some data to transmit
		case S3FSERIAL_GETACTIVECONNS : ioctl_conn = (struct ioctl_conn_param *)arg;
										if(ioctl_conn == NULL)
											return -EFAULT;

										if(copy_from_user(&tmp_ioctl_conn,ioctl_conn,sizeof(struct ioctl_conn_param)))
										{
											//printk(KERN_INFO "s3fserial::ioctl():GETACTIVECONNS : ERROR ioctl GETCONNID copy from user\n");
											return -EFAULT;		
										}

										for(i = 0; i < NR_SERIAL_DEVS; i++){
											lxc = get_lxc_entry(tmp_ioctl_conn.owner_lxc_name,i);
											if(lxc != NULL){
												//spin_lock(&devices[i].dev_lock);
												conn = lxc->connection;
												//spin_unlock(&devices[i].dev_lock);
												if(conn != NULL){
													spin_lock_irqsave(&conn->conn_lock,flags);
													//printk(KERN_INFO "s3fserial::ioctl():GETACTIVECONNS :  lxc = %s, ntx bytes = %d\n",tmp_ioctl_conn.owner_lxc_name,conn->num_bytes_to_transmit);
													if(conn->num_bytes_to_transmit)
														mask |= (1 << i);
													spin_unlock_irqrestore(&conn->conn_lock,flags);

												}
											}
											else{
												//printk(KERN_INFO "s3fserial::ioctl():GETACTIVECONNS :  Could not find = %s. conn_id = %d\n",tmp_ioctl_conn.owner_lxc_name,i);
											}
										}
										//printk(KERN_INFO "s3fserial::ioctl():GETACTIVECONNS :  lxc = %s, mask = %d\n",tmp_ioctl_conn.owner_lxc_name,mask);
										return mask;																		

		default				 :	return -ENOTTY;
	}
	return retval;

}


loff_t s3fserial_llseek(struct file * filp, loff_t pos, int whence){
	loff_t new_pos = 0;
	return new_pos;
}

int s3fserial_open(struct inode *inode, struct file *filp){

	char lxc_name[KERN_BUF_SIZE];
	struct lxc_entry * lxc;
	struct dev_struct *dev; /* device information */

	flush_buffer(lxc_name,KERN_BUF_SIZE);
	dev = container_of(inode->i_cdev, struct dev_struct, cdev);
	
	get_lxc_name(current,lxc_name);

	if(strcmp(lxc_name,"NA") == 0){
		//printk(KERN_INFO "s3fserial : Open failed\n"); // do not allow opens if the process is not inside
													   // an lxc
		filp->private_data = NULL;
		return 0;
	}
	spin_lock(&dev->dev_lock);
	lxc = hmap_get(&dev->lxcs,lxc_name);
	spin_unlock(&dev->dev_lock);

	if(!lxc){

		lxc = kmalloc(sizeof(struct lxc_entry),GFP_KERNEL);
		if(!lxc)
			return -1;
		strcpy(lxc->lxcName,lxc_name);
		lxc->PID = current->pid;
		lxc->dev = dev;
		lxc->connection = NULL;
		lxc->connection = (struct lxc_connection *)kmalloc(sizeof(struct lxc_connection),GFP_KERNEL);
		lxc->connection->num_bytes_to_transmit = 0;
		lxc->connection->num_received_bytes = 0;
		lxc->connection->recv_start = 0;
		spin_lock_init(&lxc->connection->conn_lock);
		lxc->connection->params_set = 0;

		flush_buffer(lxc->connection->tx_buf,TX_BUF_SIZE);
		flush_buffer(lxc->connection->rx_buf,RX_BUF_SIZE);
		flush_buffer(lxc->connection->dst_lxc_name,KERN_BUF_SIZE);

		spin_lock(&dev->dev_lock);
		hmap_put(&devices[dev->id].lxcs,lxc->lxcName,lxc);
		llist_append(&devices[dev->id].lxc_list,lxc->lxcName);
		printk(KERN_INFO "s3fserial::open() : Added new lxc entry for %s. Device id = %d\n",lxc->lxcName,dev->id);
		lxc->dev = dev;
		filp->private_data = lxc;
		spin_unlock(&dev->dev_lock);

		return 0;
		
	}
	spin_lock(&dev->dev_lock);
	lxc->dev = dev;
	filp->private_data = lxc;
	spin_unlock(&dev->dev_lock);

	return 0;

}

ssize_t s3fserial_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){

	struct lxc_entry * lxc = (struct lxc_entry *)filp->private_data;	
	struct lxc_connection * conn = NULL;
	struct dev_struct * dev = NULL;
	uint32_t num_rx_bytes = 0;
	char temp_rx_buff[RX_BUF_SIZE];
	uint32_t rx_start = 0;
	int fd = -1;
	int i = 0;
	unsigned long flags;
	
	if(!lxc)
		return 0; // ERROR
	dev = lxc->dev;

	if(!dev)
		return 0; // ERROR
	
	fd = dev->id;

	if(fd == -1){
		printk(KERN_INFO "s3fserial::read() : Incorrect read fd error\n");
		return 0; //
	}

	//spin_lock_irqsave(&dev->dev_lock,flags);
	conn = lxc->connection;
	//spin_unlock_irqrestore(&dev->dev_lock,flags);


	if(!conn){
		printk(KERN_INFO "s3fserial::read() : connection does not exist. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0; // ERROR
	}

	num_rx_bytes = conn->num_received_bytes;
	if(num_rx_bytes > count)
		num_rx_bytes = count;

	if(num_rx_bytes <= 0)
		return 0;

	spin_lock_irqsave(&conn->conn_lock,flags);
	
	rx_start = conn->recv_start;
	num_rx_bytes =((conn->num_received_bytes < count) ? conn->num_received_bytes : count);
	
	if(num_rx_bytes <= 0){
		spin_unlock_irqrestore(&conn->conn_lock,flags);
		//spin_unlock(&conn->conn_lock);
		//printk(KERN_INFO "s3fserial::read() : Num of bytes to read must be greater than 0. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0;
	}

	//printk(KERN_INFO "s3fserial::read() : Number of bytes to read : %d, rx_start = %d\n",num_rx_bytes,rx_start);

	for(i = 0 ; i < num_rx_bytes; i++){
		//temp_rx_buff[i] = conn->rx_buf[mod(rx_start + i, RX_BUF_SIZE)];
		if(rx_start + i >= RX_BUF_SIZE)			
			temp_rx_buff[i] = conn->rx_buf[rx_start + i - RX_BUF_SIZE];
		else
			temp_rx_buff[i] = conn->rx_buf[rx_start + i];
	}

	int orig_num_received_bytes = conn->num_received_bytes;
	int orig_recv_start = conn->recv_start;

	conn->num_received_bytes -= num_rx_bytes;
	if(conn->num_received_bytes == 0)
		conn->recv_start = 0;
	else{
		//conn->recv_start = mod(conn->recv_start + num_rx_bytes, RX_BUF_SIZE);
		if(conn->recv_start + num_rx_bytes >= RX_BUF_SIZE)
			conn->recv_start = conn->recv_start + num_rx_bytes - RX_BUF_SIZE;
		else 
			conn->recv_start = conn->recv_start + num_rx_bytes;
	}

	
	
	spin_unlock_irqrestore(&conn->conn_lock,flags);
	
	

	if(copy_to_user(buf,temp_rx_buff,num_rx_bytes)){
		spin_lock_irqsave(&conn->conn_lock,flags);	
		conn->num_received_bytes = orig_num_received_bytes;
		conn->recv_start = orig_recv_start;

		spin_unlock_irqrestore(&conn->conn_lock,flags);
		printk(KERN_INFO "s3fserial::read() : ERROR copy to user. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return -EFAULT;
	}
	
	/*spin_lock_irqsave(&conn->conn_lock,flags);
	
	conn->num_received_bytes -= num_rx_bytes;
	if(conn->num_received_bytes == 0)
		conn->recv_start = 0;
	else{
		//conn->recv_start = mod(conn->recv_start + num_rx_bytes, RX_BUF_SIZE);
		if(conn->recv_start + num_rx_bytes >= RX_BUF_SIZE)
			conn->recv_start = conn->recv_start + num_rx_bytes - RX_BUF_SIZE;
		else 
			conn->recv_start = conn->recv_start + num_rx_bytes;
	}

	spin_unlock_irqrestore(&conn->conn_lock,flags);*/
	
	

	return num_rx_bytes;

}

ssize_t s3fserial_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos){

	struct lxc_entry * lxc = (struct lxc_entry *)filp->private_data;	
	struct lxc_connection * conn = NULL;
	struct dev_struct * dev = NULL;
	uint32_t num_tx_bytes = 0;
	char temp_tx_buff[TX_BUF_SIZE];
	uint32_t tx_start = 0;
	uint32_t max_available_space = 0;
	int fd = -1;
	int i = 0;
	unsigned long flags;

	if(!lxc)
		return 0; // ERROR
	dev = lxc->dev;

	if(!dev)
		return 0; // ERROR
	
	fd = dev->id;

	if(fd == -1){
		printk(KERN_INFO "s3fserial::write() : Incorrect write fd error\n");
		return 0; //
	}



	//spin_lock_irqsave(&dev->dev_lock,flags);
	conn = lxc->connection;
	//spin_unlock_irqrestore(&dev->dev_lock,flags);

	if(!conn){
		printk(KERN_INFO "s3fserial::write() : connection does not exist. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0; // ERROR
	}

	spin_lock_irqsave(&conn->conn_lock,flags);
	tx_start = conn->num_bytes_to_transmit;
	spin_unlock_irqrestore(&conn->conn_lock,flags);

	max_available_space = TX_BUF_SIZE - tx_start;
	num_tx_bytes = ((max_available_space < count ? max_available_space : count));

	if(num_tx_bytes <= 0){
		
		printk(KERN_INFO "s3fserial::write() : Num of bytes to write must be greater than 0. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0;
	}

	if(copy_from_user(temp_tx_buff,buf,num_tx_bytes)){
		printk(KERN_INFO "s3fserial::write() : ERROR copy from user. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0;
	}

	
	spin_lock_irqsave(&conn->conn_lock,flags);
	for(i = 0; i < num_tx_bytes; i++){
		conn->tx_buf[mod(tx_start + i, TX_BUF_SIZE)] = temp_tx_buff[i];
	}

	conn->num_bytes_to_transmit += num_tx_bytes;
	//printk(KERN_INFO "s3fserial::write() : Write successfull for lxc : %s. Num bytes to transmit : %d\n",lxc->lxcName,conn->num_bytes_to_transmit);
	spin_unlock_irqrestore(&conn->conn_lock,flags);

	return num_tx_bytes;


}

uint32_t s3fserial_poll(struct file *filp, poll_table *wait){

	uint32_t mask = 0;
	struct lxc_entry * lxc = (struct lxc_entry *)filp->private_data;	
	struct lxc_connection * conn = NULL;
	struct dev_struct * dev = NULL;
	int fd = -1;
	unsigned long flags;
	
	if(!lxc)
		return 0; // ERROR
	dev = lxc->dev;

	if(!dev)
		return 0; // ERROR
	
	fd = dev->id;

	//spin_lock(&dev->dev_lock);
	conn = lxc->connection;
	//spin_unlock(&dev->dev_lock);

	if(!conn){
		printk(KERN_INFO "s3fserial::poll() : connection does not exist. lxc : %s, conn_id %d\n",lxc->lxcName,fd);
		return 0; // ERROR
	}

	spin_lock(&conn->conn_lock);
	int tx_space = TX_BUF_SIZE - conn->num_bytes_to_transmit;
	int n_rx_bytes = conn->num_received_bytes;
	spin_unlock(&conn->conn_lock);
	//printk(KERN_INFO "s3fserial::poll() : lxc : %s, conn_id %d\n",lxc->lxcName,fd);
	if(tx_space > 0)
		mask |= POLLOUT | POLLWRNORM;   /* writable */
	if(n_rx_bytes > 0)
		mask |= POLLIN | POLLRDNORM;   /* readable */
	

	return mask;

}


int s3fserial_release(struct inode *inode, struct file *filp){
	return 0;
}



int init_s3fserial(void){

	int result, i;
	dev_t dev = 0;


	if(dev_major){

		dev = MKDEV(dev_major, dev_minor);
		result = register_chrdev_region(dev, nr_devs, "s3fserial");

	} else {

		result = alloc_chrdev_region(&dev, dev_minor, nr_devs,"s3fserial");
		dev_major = MAJOR(dev);
	}

	if (result < 0) {
		printk(KERN_WARNING "s3fserial::init() : can't get major %d\n", dev_major);
		return result;
	}

	devices = kmalloc(nr_devs * sizeof(struct dev_struct), GFP_KERNEL);

	if(!devices){
		result = -ENOMEM;
		cleanup_s3fserial();
		return result;
	}

	for(i = 0; i < nr_devs; i++){

		spin_lock_init(&devices[i].dev_lock);
		devices[i].id = i;
		hmap_init( &devices[i].lxcs,"string",0);
		llist_init(&devices[i].lxc_list);
		//init_MUTEX(&devices[i].sem);
		int err, devno = MKDEV(dev_major, dev_minor + i);
    
		cdev_init(&devices[i].cdev, &dev_fops);
		devices[i].cdev.owner = THIS_MODULE;
		devices[i].cdev.ops = &dev_fops;
		err = cdev_add(&devices[i].cdev, devno, 1);
		/* Fail gracefully if need be */
		if (err)
			printk(KERN_NOTICE "s3fserial::init() : Error %d adding device%d", err, i);

	}

	return 0;



}



int cleanup_s3fserial(void){

	int i;
	dev_t devno = MKDEV(dev_major, dev_minor);
	char * next_lxcName = NULL;
	struct lxc_entry * lxc = NULL;	
	struct lxc_connection * conn = NULL;
	struct dev_struct * dev = NULL;
	
	/* Get rid of our char dev entries */
	if (devices) {
		for (i = 0; i < NR_SERIAL_DEVS; i++) {
			cdev_del(&devices[i].cdev);

			while(llist_size(&devices[i].lxc_list) > 0){
				next_lxcName = llist_pop(&devices[i].lxc_list);
				if(next_lxcName != NULL){
					printk(KERN_INFO "s3fserial::cleanup() at lxc = %s\n",next_lxcName);
					lxc = hmap_get(&devices[i].lxcs,next_lxcName);					
					if(lxc != NULL){
						hmap_remove(&devices[i].lxcs,lxc->lxcName);
						if(!lxc->connection){
							kfree(lxc);	
						}
						else{
							kfree(lxc->connection);
							kfree(lxc);	
						}
					}				
				}

			}			
			hmap_destroy(&devices[i].lxcs);
			llist_destroy(&devices[i].lxc_list);
		}

		kfree(devices);
	}

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, NR_SERIAL_DEVS);

	return 0;

}

module_init(init_s3fserial);
module_exit(cleanup_s3fserial);
