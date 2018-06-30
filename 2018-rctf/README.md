## stringer
patial off-by-one and double-free
leaking libc address is a problem.
see the source code of calloc().
```
 /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))
        return memset (mem, 0, sz);

      return mem;
    }
```

## Rnote3
```
struct note
{
	char title[8];
	int size;
	char *content;
}
```
varible ptr is not initialized, causing double free.

## Rnote4
heap overflow. 
Learn another skill! Overwrite strtab(releated to dl-resolve).
```
typedef struct {
        Elf64_Xword d_tag;
        union {
                Elf64_Xword     d_val;
                Elf64_Addr      d_ptr;
        } d_un;
} Elf64_Dyn;
```
Just need to get the free's offset in strtab.

## Babyheap
Null-byte off-by-noe, I forgot to save my previous script about this type of exploitation. I think you can use the same script if you meet this kind loophole, just change the new, edit, delete functions. I take the official script here(lazy to write).