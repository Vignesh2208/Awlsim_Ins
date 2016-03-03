#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h> 
#include <sys/ioctl.h>
#include <fcntl.h>



#define NR_SERIAL_DEVS        3
#define NR_DEVS 1
#define KERN_BUF_SIZE 100
#define TX_BUF_SIZE 100
#define RX_BUF_SIZE 2*(TX_BUF_SIZE)


#define S3FSERIAL_IOC_MAGIC  'k'
#define S3FSERIAL_IOWRX _IOW(S3FSERIAL_IOC_MAGIC,  1, int) // write to the rx buffer from user space. used by S3F simulator.
#define S3FSERIAL_IORTX _IOR(S3FSERIAL_IOC_MAGIC,  2, int) // read the tx buffer into user space. used by S3F simulator.
#define S3FSERIAL_SETCONNLXC _IOW(S3FSERIAL_IOC_MAGIC,  3, int) // set the dest_lxc_name for conneciton passed as param. used by AWLSIM
#define S3FSERIAL_GETCONNLXC _IOR(S3FSERIAL_IOC_MAGIC,  4, int) // get the dest_lxc_name for connection passed as param. used by S3F
#define S3FSERIAL_GETCONNID _IOR(S3FSERIAL_IOC_MAGIC,  5, int) // get the CONN_ID for connection SPECIFIED BY TWO LXCS as param. used by S3F
#define S3FSERIAL_GETCONNSTATUS _IOR(S3FSERIAL_IOC_MAGIC, 6, int)
#define S3FSERIAL_GETACTIVECONNS _IOR(S3FSERIAL_IOC_MAGIC,7,int)


struct ioctl_conn_param{

	int conn_id;						
	char owner_lxc_name[KERN_BUF_SIZE];	
	char dst_lxc_name[KERN_BUF_SIZE];
	int num_bytes_to_write;			 // number of bytes to write to rxbuf
	char bytes_to_write[RX_BUF_SIZE];// buffer from which data is copied to lxc's rx_buf
	int num_bytes_to_read;			 // number of bytes to read from txbuf
	char bytes_to_read[TX_BUF_SIZE]; // buffer to which data from txbuf is copied.
};

void flush_buffer(char * buf, int size){
	int i = 0;
	for(i = 0; i < size; i++)
		buf[i] = '\0';
}

void reset_ioctl_conn(struct ioctl_conn_param * ioctl_conn){
	flush_buffer(ioctl_conn->owner_lxc_name,KERN_BUF_SIZE);
	flush_buffer(ioctl_conn->dst_lxc_name,KERN_BUF_SIZE);
  	flush_buffer(ioctl_conn->bytes_to_write,RX_BUF_SIZE);
  	flush_buffer(ioctl_conn->bytes_to_read,TX_BUF_SIZE);
  	ioctl_conn->conn_id = 0;
  	ioctl_conn->num_bytes_to_write = 0;
  	ioctl_conn->num_bytes_to_read = 0;
}


void main(){

	int fd;
	int i = 0;
	struct ioctl_conn_param ioctl_conn;

	//return;

	fd = open("/dev/s3fserial0",O_RDWR);
	reset_ioctl_conn(&ioctl_conn);
	strcpy(ioctl_conn.owner_lxc_name,"lxc0-0");
	ioctl_conn.conn_id = 0;
	strcpy(ioctl_conn.dst_lxc_name,"lxc1-0");
	if(ioctl(fd,S3FSERIAL_SETCONNLXC,&ioctl_conn) < 0){
		fprintf(stdout,"Client : Ioctl SETCONNLXC error\n");
		fflush(stdout);
		close(fd);
		return;
	}


	int ret = 0;
	int len = 250;
	int n_copied = 0;
	char msg[251];

	flush_buffer(msg,len + 1);

	for(i = 0; i < 250; i++)
		msg[i] = 'H';

	fprintf(stdout,"Client : Sending Data\n");
	fflush(stdout);

	while(n_copied < len){
		ret = write(fd,msg + n_copied,len - n_copied);
		if(ret < 0){
			fprintf(stdout,"Client : ERROR with write\n");
			fflush(stdout);
			close(fd);
			return;
		}
		else if(ret == 0)
			usleep(100000);

		n_copied = n_copied + ret;
	}

	fprintf(stdout,"Client : Data sent\n");
	fflush(stdout);
	close(fd);



}