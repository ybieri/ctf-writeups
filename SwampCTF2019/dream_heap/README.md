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

The binary has two arrays stored in the .bss section. HEAP_PTRS[8] and SIZES[8]. HEAP_PTRS contains pointers to the dreams you allocated and SIZES contains the size of the dream you allocated. Above them is a variable called INDEX, that holds the amount of dreams you allocated.

We can leak an address using the `Read dream` function:

```unsigned __int64 read_dream()
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
The index <= INDEX is a signed comparison, thus we can provide a negative index. If we can provide a pointer to a GOT entry, ` printf("%s", dream)` will leak the corresponding libc address. Starting at `0x000000000400520` we have the ELF JMPREL Relocation Table that holds pointers to the GOT.
Thus by providing the correct negative offset we can leak a libc address and defeat ASLR.

