extern int main();
long exit(long status){
	
	asm volatile(
        "mov r0,%0\n\t"
	"mov r7,#1\n\t"
        "svc 0\n\t"
	:
	:"r"(status)
	:"r0","r7"
	);

}

void _start(){
	int ret = main();
	exit(ret);
}
long mmap(void* addr,long size,long prot,long flag,long offset){
	long ret;
	asm volatile(
	"mov r0,%1\n\t"
	"mov r1,%2\n\t"
	"mov r2,%3\n\t"
	"mov r3,%4\n\t"
	"mov r4,%5\n\t"
	"mov r7,#192\n\t"
	"svc 0\n\t"
	"mov %0,r0\n\t"
	:"=r"(ret)
	:"r"(addr),"r"(size),"r"(prot),"r"(flag),"r"(offset)
	:"r0","r1","r2","r3","r4","r5","r7"
	);
	return ret;
}

long prctl(long a,long b){
	long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
	"mov r7,#0xac\n\t"
	"svc 0\n\t"
	"mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(a),"r"(b)
        :"r0","r1","r7"
        );
        return ret;

}


long open(long name,long flag){
        long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
        "eor r2,r2\n\t"
        "mov r7,#5\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(name),"r"(flag)
        :"r0","r1","r2","r7"
        );
        return ret;

}
long read(long fd,long addr,long size){
	long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
        "mov r2,%3\n\t"
        "mov r7,#3\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(fd),"r"(addr),"r"(size)
        :"r0","r1","r2","r7"
        );
        return ret;

}
long write(long fd,long addr,long size){
	long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
        "mov r2,%3\n\t"
        "mov r7,#4\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(fd),"r"(addr),"r"(size)
        :"r0","r1","r2","r7"
        );
        return ret;

}
long fork(){
	long ret;
        asm volatile(
	"mov r7,#2\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
	:"=r"(ret)
	:
	:"r0","r7"
	);
	return ret;
}

long pipe(int* fd){
        long ret;
        asm volatile(
	"mov r0,%1\n\t"
        "mov r7,#0x2a\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(fd)
        :"r0","r7"
        );
        return ret;
}

long close(int fd){
        long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r7,#6\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(fd)
        :"r0","r7"
        );
        return ret;
}

long getuid(){
        long ret;
        asm volatile(
        "mov r7,#0x18\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :
        :"r0","r7"
        );
        return ret;
}
int strlen(char* buf){
	int i= 0;
	while(buf[i]) i++;
	return i;
}
void puts(char* msg){
	write(1,msg,strlen(msg));
	write(1,"\n",1);
}

void itoa(int a,char* b){
	int total = 0;
	int num = a;
	while(a){
		total+=1;
		a/=10;
	}	
	b[total] = 0;
	while(total){
		b[total-1] = '0'+ (num%10);
		num/=10;
		total-=1;
	}
}

void memset(char* addr,char val,long size){
	while(size) 
		addr[--size] = val;
}

void perror(char* msg){
	puts(msg);
}

long execve(char* path,char** arg,char** env){
        long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
        "mov r2,%3\n\t"
        "mov r7,#0xb\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(path),"r"(arg),"r"(env)
        :"r0","r1","r2","r7"
        );
        return ret;

}
long wait(){
	int status;
	int val = -1;
	int* val2 = &status;
	long ret;
        asm volatile(
        "mov r0,%1\n\t"
        "mov r1,%2\n\t"
        "eor r2,r2\n\t"
	"eor r3,r3\n\t"
        "mov r7,#114\n\t"
        "svc 0\n\t"
        "mov %0,r0\n\t"
        :"=r"(ret)
        :"r"(val),"r"(val2)
        :"r0","r1","r2","r3","r7"
        );
        return ret;
}
